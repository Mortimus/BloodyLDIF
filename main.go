package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/go-ldap/ldif"
)

// remove /tmp/c0a97d4e8f1f2bc301e54564213140da.cache before running ldif2bloodhound

func main() {
	inputFlag := flag.String("input", "", "Input file path")
	outputFlag := flag.String("output", "", "Output file path")
	// Parse command-line flags
	flag.Parse()
	var missingFlags bool

	if *inputFlag == "" {
		fmt.Println("Input file path is required.")
		missingFlags = true
	}
	if *outputFlag == "" {
		fmt.Println("Output file path is required.")
		missingFlags = true
	}
	if missingFlags {
		flag.Usage()
		fmt.Printf("Dump bloodhound data using BloodyAD (which uses LDAP session encryption)\n")
		fmt.Printf("bloodyAD --host 127.0.0.1 -u lowpriv -p 'password' -d contoso.local get search --filter '(objectClass=*)' --raw >> out.ldif\n")
		fmt.Printf("bloodyAD --host 127.0.0.1 -u lowpriv -p 'password' -d contoso.local get search --base 'CN=Schema,CN=Configuration,DC=contoso,DC=local' --filter '(objectClass=*)' --raw >> out.ldif\n")
		return
	}
	// Read the input file
	// Check if the input file exists
	if _, err := os.Stat(*inputFlag); os.IsNotExist(err) {
		fmt.Printf("Input file %s does not exist.\n", *inputFlag)
		missingFlags = true
	}

	dat, err := readBloodyAD(*inputFlag)
	if err != nil {
		fmt.Println("Error loading BloodyAD:", err)
		return
	}
	// expand combined variables
	dat, err = expandCombinedVariables(dat)
	if err != nil {
		fmt.Println("Error expanding combined variables:", err)
		return
	}
	// Fix missing dn lines
	dat, err = addDN(dat)
	if err != nil {
		fmt.Println("Error adding DN:", err)
		return
	}
	// Fix base64 lines
	dat, err = fixBase64Lines(dat)
	if err != nil {
		fmt.Println("Error fixing base64 lines:", err)
		return
	}

	// Write the modified data to a new file
	err = writeToFile(*outputFlag, dat)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	// Check if valid LDIF
	_, err = loadLDIF(dat)
	if err != nil {
		fmt.Println("Error loading LDIF:", err)
		var lineNumber int
		_, err2 := fmt.Sscanf(err.Error(), "Error in line %d:", &lineNumber)
		if err2 != nil {
			fmt.Printf("Error reading line: %s\n", err2.Error())
		} else {
			fmt.Printf("Problematic lines %d: %s\n", lineNumber-2, getSliceLine(dat, lineNumber-2))
			fmt.Printf("Problematic lines %d: %s\n", lineNumber-1, getSliceLine(dat, lineNumber-1))
			fmt.Printf("Problematic lines %d: %s\n", lineNumber, getSliceLine(dat, lineNumber))
			fmt.Printf("Problematic lines %d: %s\n", lineNumber+1, getSliceLine(dat, lineNumber+1))
			fmt.Printf("Problematic lines %d: %s\n", lineNumber+2, getSliceLine(dat, lineNumber+2))
		}
		return
	}
	fmt.Printf("LDIF converted successfully, now run ldif2bloodhound.py\n")
	// Print the LDIF
	// fmt.Printf("LDIF: %+v\n", ldif)
}

func loadLDIF(dat []byte) (*ldif.LDIF, error) {
	// Create a new LDIF reader
	out, err := ldif.Parse(string(dat))
	if err != nil {
		return nil, err
	}

	return out, nil
}

/*
bloodyAD --host 127.0.0.1 -u lowpriv -p 'password' -d contoso.local get search --filter '(objectClass=*)' --raw > out.ldif
bloodyAD --host 127.0.0.1 -u lowpriv -p 'password' -d contoso.local get search --base 'CN=Schema,CN=Configuration,DC=contoso,DC=local' --filter '(objectClass=*)' --raw >> out.ldif
*/
func readBloodyAD(path string) ([]byte, error) {
	dat, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

// loop through dat and and add dn: to the line before distinguishedName:
func addDN(dat []byte) ([]byte, error) {
	// --- 3. Define Prefix and Newline ---
	prefixBytes := []byte("distinguishedName:") // The prefix to search for
	dnPrefixBytes := []byte("dn: ")             // The prefix for the new line to insert
	newlineBytes := []byte("\n")                // Use standard newline for output buffer

	// --- 4. Process Data Line by Line ---
	var outputBuffer bytes.Buffer // Use bytes.Buffer for efficient output building

	lines := bytes.Split(dat, newlineBytes) // Split input into lines

	numLines := len(lines)
	for i, line := range lines {
		// Handle potential empty last element from Split if file ends with newline
		isLastElementFromSplit := (i == numLines-1)
		if isLastElementFromSplit && len(line) == 0 {
			continue // Skip processing the empty part after the last newline
		}

		// Trim potential \r from end of line (for Windows/mixed line endings) before comparison/writing
		trimmedLine := bytes.TrimSuffix(line, []byte("\r"))

		// Check if the trimmed line starts with the target prefix "distinguishedName:"
		if bytes.HasPrefix(trimmedLine, prefixBytes) {
			// --- Match found ---

			// Extract the value part (RANDOM_STRING_HERE)
			// This slices the byte array starting right after the prefix
			// bytes.TrimSpace removes leading/trailing whitespace from this extracted value
			valueBytes := bytes.TrimSpace(trimmedLine[len(prefixBytes):])

			// Construct the line to insert: "dn: RANDOM_STRING_HERE"
			lineToInsert := append(dnPrefixBytes, valueBytes...) // Combine "dn:" and the extracted value

			// Write the insertion line FIRST to the buffer
			outputBuffer.Write(lineToInsert)
			outputBuffer.Write(newlineBytes) // Add newline

			// Then write the original matched line (trimmed) to the buffer
			outputBuffer.Write(trimmedLine)
			outputBuffer.Write(newlineBytes) // Add newline

		} else {
			// --- No match: Write the original line (trimmed) back to the buffer ---
			outputBuffer.Write(trimmedLine)
			outputBuffer.Write(newlineBytes) // Add newline
		}
	}

	// --- Adjust for Trailing Newline ---
	// This section ensures the output file ends with a newline only if the input file did.
	finalOutputBytes := outputBuffer.Bytes()
	// Check if original data did NOT end with newline AND buffer is not empty
	if !bytes.HasSuffix(dat, newlineBytes) && len(finalOutputBytes) > 0 {
		// Check if the buffer currently ends with a newline we might have added
		if finalOutputBytes[len(finalOutputBytes)-1] == '\n' {
			// Remove the potentially added trailing newline
			finalOutputBytes = finalOutputBytes[:len(finalOutputBytes)-1]
		}
	}
	return finalOutputBytes, nil
}

func getSliceLine(dat []byte, line int) string {
	// Split the data into lines
	lines := bytes.Split(dat, []byte("\n"))
	if line < 0 || line >= len(lines) {
		return ""
	}
	return string(lines[line])
}

func fixBase64Lines(dat []byte) ([]byte, error) {
	// List of variable names that require double colons
	variableNames := []string{ // Everything after "schemaIDGUID" is unique to bloodyAD
		"adminDescription", "attributeSecurityGUID", "auditingPolicy", "dnsRecord", "dSASignature",
		"ipsecData", "logonHours", "msDFSR-ContentSetGuid", "msDFSR-ReplicationGroupGuid",
		"msDS-GenerationId", "nTSecurityDescriptor", "objectGUID", "objectSid", "oMObjectClass",
		"samDomainUpdates", "schemaIDGUID", "replUpToDateVector", "repsFrom", "repsTo",
	}

	// Convert variable names to a map for quick lookup
	variableMap := make(map[string]struct{})
	for _, name := range variableNames {
		variableMap[name] = struct{}{}
	}

	// Split the input data into lines
	lines := bytes.Split(dat, []byte("\n"))
	var outputBuffer bytes.Buffer

	for _, line := range lines {
		trimmedLine := bytes.TrimSpace(line)

		// Check if the line contains a colon and split it into parts
		parts := bytes.SplitN(trimmedLine, []byte(": "), 2)
		if len(parts) == 2 {
			varName := string(bytes.TrimSpace(parts[0]))
			// Check if the variable name is in the map and if it only has one colon
			if _, exists := variableMap[varName]; exists && !bytes.HasPrefix(parts[1], []byte(":")) {
				// check if the data is base64 encoded
				encoded := parts[1]
				if !isBase64(encoded) {
					// If the data is not base64 encoded, encode it
					encoded = []byte(base64.StdEncoding.EncodeToString(encoded))
				} else {
					// DEBUG
					// fmt.Printf("Not base64: %s\n", string(encoded))
				}
				// test ldif func and force encode if failure
				_, err := decodeBase64(string(encoded))
				if err != nil {
					encoded = []byte(base64.StdEncoding.EncodeToString(encoded))
				}
				// Add an extra colon to the line
				line = append(parts[0], append([]byte(":: "), encoded...)...)
			}
		}

		// Write the line to the output buffer
		outputBuffer.Write(line)
		outputBuffer.Write([]byte("\n"))
	}

	return outputBuffer.Bytes(), nil
}

func writeToFile(path string, data []byte) error {
	// Write the modified data to a new file
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// expand combined variables based on a map of known variables such as objectClass so objectClass: top;domain;domainDNS; should be 3 lines
func expandCombinedVariables(dat []byte) ([]byte, error) {
	// List of variable names that require expansion
	variableNames := []string{
		"objectClass", "memberOf", "member",
	}

	// Convert variable names to a map for quick lookup
	variableMap := make(map[string]struct{})
	for _, name := range variableNames {
		variableMap[name] = struct{}{}
	}

	// Split the input data into lines
	lines := bytes.Split(dat, []byte("\n"))
	var outputBuffer bytes.Buffer

	for _, line := range lines {
		trimmedLine := bytes.TrimSpace(line)

		// Check if the line contains a colon and split it into parts
		parts := bytes.SplitN(trimmedLine, []byte(":"), 2)
		if len(parts) == 2 {
			varName := string(bytes.TrimSpace(parts[0]))
			// Check if the variable name is in the map and if it has combined values
			if _, exists := variableMap[varName]; exists && bytes.Contains(parts[1], []byte(";")) {
				values := bytes.Split(parts[1], []byte(";"))
				for _, value := range values {
					outputBuffer.Write(parts[0])
					outputBuffer.Write([]byte(":"))
					outputBuffer.Write(value)
					outputBuffer.Write([]byte("\n"))
				}
				continue // Skip writing the original line
			}
		}

		// Write the line to the output buffer
		outputBuffer.Write(line)
		outputBuffer.Write([]byte("\n"))
	}

	return outputBuffer.Bytes(), nil
}

// check if input bytes are base64 encoded
func isBase64(data []byte) bool {
	// Check if the data is empty
	if len(data) == 0 {
		return false
	}

	// Check if the data contains only valid base64 characters
	for _, b := range data {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '+' && b != '/' && b != '=' {
			return false
		}
	}

	// Decode the base64 data and check for errors
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// ripped from ldif library
func decodeBase64(enc string) (string, error) {
	dec := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(enc))))
	n, err := base64.StdEncoding.Decode(dec, []byte(enc))
	if err != nil {
		return "", err
	}
	return string(dec[:n]), nil
}

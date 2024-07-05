package main

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var (
	// Local LLDP Information OIDs
	lldpLocChassisID = ".1.0.8802.1.1.2.1.3.2.0"
	lldpLocSysName   = ".1.0.8802.1.1.2.1.3.3.0"
	lldpLocPortDesc  = ".1.0.8802.1.1.2.1.3.7.1.3"

	// Additional OIDs
	sysDesc   = ".1.3.6.1.2.1.1.1.0"       // System Description
	sysVendor = ".1.3.6.1.4.1.8072.3.2.10" // sysVendor (assuming for the example)

	// Remote LLDP Information OIDs
	lldpRemChassisID   = ".1.0.8802.1.1.2.1.4.1.1.5"
	lldpRemPortID      = ".1.0.8802.1.1.2.1.4.1.1.7"
	lldpRemPortDesc    = ".1.0.8802.1.1.2.1.4.1.1.8"
	lldpRemSysName     = ".1.0.8802.1.1.2.1.4.1.1.9"
	lldpRemSysCap      = ".1.0.8802.1.1.2.1.4.1.1.12"
	lldpRemMgmtAddress = ".1.0.8802.1.1.2.1.4.2.1.4"
	lldpRemTable       = ".1.0.8802.1.1.2.1.4.1"
)

func main() {
	input := "input.csv"
	output := "lldp_info.csv"

	records, err := readCSV(input)
	if err != nil {
		log.Fatalf("Error reading input CSV file: %v", err)
	}

	allLocalInfo := make(map[string]map[string]string)
	allRemoteInfo := make(map[string][]map[string]string)

	for _, record := range records {
		if len(record) < 2 {
			log.Printf("Skipping invalid record: %v\n", record)
			continue
		}
		target := record[0]
		community := record[1]

		snmp := initializeSNMP(target, community)
		defer snmp.Conn.Close()

		localInfo, err := fetchLocalLLDP(snmp)
		if err != nil {
			log.Printf("Error fetching local LLDP info for %s: %v\n", target, err)
			continue
		}

		remoteInfo, err := fetchRemoteLLDP(snmp)
		if err != nil {
			log.Printf("Error fetching remote LLDP info for %s: %v\n", target, err)
			continue
		}

		allLocalInfo[target] = localInfo
		allRemoteInfo[target] = remoteInfo
	}

	err = writeBatchCSV(output, allLocalInfo, allRemoteInfo)
	if err != nil {
		log.Fatalf("Error writing output CSV file: %v", err)
	}

	log.Printf("LLDP information successfully written to %s", output)
}

func initializeSNMP(target, community string) *gosnmp.GoSNMP {
	snmp := &gosnmp.GoSNMP{
		Target:    target,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(5) * time.Second,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		log.Fatalf("Error connecting to target %s: %v", target, err)
	}

	return snmp
}

func fetchLocalLLDP(snmp *gosnmp.GoSNMP) (map[string]string, error) {
	localOids := []string{lldpLocChassisID, lldpLocSysName, lldpLocPortDesc, sysDesc, sysVendor}
	localInfo, err := snmp.Get(localOids)
	if err != nil {
		return nil, fmt.Errorf("error getting local LLDP info: %v", err)
	}

	result := make(map[string]string)
	for _, variable := range localInfo.Variables {
		value := parseSNMPVariable(variable)
		switch variable.Name {
		case lldpLocChassisID:
			result["Local Chassis ID"] = value
		case lldpLocSysName:
			result["Local System Name"] = value
		case lldpLocPortDesc:
			result["Local Port Description"] = value
		case sysDesc:
			result["System Description"] = value
		case sysVendor:
			result["System Vendor"] = value
		}
	}
	return result, nil
}

func fetchRemoteLLDP(snmp *gosnmp.GoSNMP) ([]map[string]string, error) {
	remoteInfo, err := snmp.WalkAll(lldpRemTable)
	if err != nil {
		return nil, fmt.Errorf("error getting remote LLDP info: %v", err)
	}

	results := []map[string]string{}
	current := make(map[string]string)

	log.Println("Starting SNMP walk on remote LLDP table")
	for _, variable := range remoteInfo {
		value := parseSNMPVariable(variable)
		log.Printf("OID: %s, Value: %s", variable.Name, value)
		switch {
		case strings.HasPrefix(variable.Name, lldpRemChassisID):
			current["Remote Chassis ID"] = value
		case strings.HasPrefix(variable.Name, lldpRemPortID):
			current["Remote Port ID"] = value
		case strings.HasPrefix(variable.Name, lldpRemPortDesc):
			current["Remote Port Description"] = value
		case strings.HasPrefix(variable.Name, lldpRemSysName):
			current["Remote System Name"] = value
		case strings.HasPrefix(variable.Name, lldpRemSysCap):
			current["Remote System Capabilities"] = value
		case strings.HasPrefix(variable.Name, lldpRemMgmtAddress):
			current["Remote Management Address"] = value
		}

		// Check if we have a complete set and append
		if hasAllKeys(current) {
			results = append(results, current)
			current = make(map[string]string)
		}
	}

	// Append the last set of data if it's not empty
	if len(current) > 0 {
		results = append(results, current)
	}
	return results, nil
}

func hasAllKeys(data map[string]string) bool {
	requiredKeys := []string{
		"Remote Chassis ID",
		"Remote Port ID",
		"Remote Port Description",
		"Remote System Name",
		"Remote System Capabilities",
		"Remote Management Address",
	}
	for _, key := range requiredKeys {
		if _, ok := data[key]; !ok {
			return false
		}
	}
	return true
}

func parseSNMPVariable(variable gosnmp.SnmpPDU) string {
	switch variable.Type {
	case gosnmp.OctetString:
		value := variable.Value.([]byte)
		// Check if the byte slice contains mostly printable characters
		if isMostlyPrintable(value) {
			return string(value)
		}
		// Fallback to hex encoding for non-printable characters
		return hex.EncodeToString(value)
	default:
		if variable.Value == nil {
			return "<nil>"
		}
		return fmt.Sprintf("%v", variable.Value)
	}
}

func isMostlyPrintable(data []byte) bool {
	nonPrintableCount := 0
	for _, b := range data {
		if (b < 32 || b > 126) && b != 10 && b != 13 { // Allow newline and carriage return
			nonPrintableCount++
		}
	}
	// Consider the data printable if more than 90% of the characters are printable
	return nonPrintableCount < len(data)/10
}

func readCSV(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	return records, nil
}

func writeBatchCSV(filename string, localInfo map[string]map[string]string, remoteInfo map[string][]map[string]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Type", "Target", "Description", "Value"}
	writer.Write(headers)

	for target, info := range localInfo {
		for desc, value := range info {
			writer.Write([]string{"Local", target, desc, value})
		}
	}

	for target, infos := range remoteInfo {
		for _, info := range infos {
			for desc, value := range info {
				writer.Write([]string{"Remote", target, desc, value})
			}
		}
	}
	return nil
}

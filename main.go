package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var (
	lldpLocChassisID = ".1.0.8802.1.1.2.1.3.2.0"
	lldpLocSysName   = ".1.0.8802.1.1.2.1.3.3.0"
	lldpRemTable     = ".1.0.8802.1.1.2.1.4.1"
)

func main() {
	input := "input.csv"
	output := "lldp_info.csv"

	records, err := readCSV(input)
	if err != nil {
		log.Fatalf("Error reading input CSV file: %v", err)
	}

	allLocalInfo := make(map[string]map[string]string)
	allRemoteInfo := make(map[string]map[string]map[string]string)

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
	localOids := []string{lldpLocChassisID, lldpLocSysName}
	localInfo, err := snmp.Get(localOids)
	if err != nil {
		return nil, fmt.Errorf("error getting local LLDP info: %v", err)
	}

	result := make(map[string]string)
	for _, variable := range localInfo.Variables {
		value := parseSNMPVariable(variable)
		result[variable.Name] = value
	}
	return result, nil
}

func fetchRemoteLLDP(snmp *gosnmp.GoSNMP) (map[string]map[string]string, error) {
	remoteInfo, err := snmp.WalkAll(lldpRemTable)
	if err != nil {
		return nil, fmt.Errorf("error getting remote LLDP info: %v", err)
	}

	result := make(map[string]map[string]string)
	for _, variable := range remoteInfo {
		oidParts := parseOID(variable.Name)
		if len(oidParts) < 3 {
			continue
		}
		id := oidParts[len(oidParts)-3]
		subOid := oidParts[len(oidParts)-2]

		if _, ok := result[id]; !ok {
			result[id] = make(map[string]string)
		}
		result[id][subOid] = parseSNMPVariable(variable)
	}
	return result, nil
}

func parseSNMPVariable(variable gosnmp.SnmpPDU) string {
	switch variable.Type {
	case gosnmp.OctetString:
		return string(variable.Value.([]byte))
	default:
		return fmt.Sprintf("%v", variable.Value)
	}
}

func parseOID(oid string) []string {
	return strings.Split(oid, ".")
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

func writeBatchCSV(filename string, localInfo map[string]map[string]string, remoteInfo map[string]map[string]map[string]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Type", "Target", "ID", "OID", "Value"}
	writer.Write(headers)

	for target, info := range localInfo {
		for oid, value := range info {
			writer.Write([]string{"Local", target, "", oid, value})
		}
	}

	for target, info := range remoteInfo {
		for id, subInfo := range info {
			for oid, value := range subInfo {
				writer.Write([]string{"Remote", target, id, oid, value})
			}
		}
	}
	return nil
}

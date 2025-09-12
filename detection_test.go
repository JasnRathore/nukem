package main

import (
	"fmt"
	d "nukem/detection"
	"testing"
)

/*
	func Add(a, b int) int {
		return a + b
	}

	func TestAdd(t *testing.T) {
		result := Add(2, 3)
		expected := 5

		if result != expected {
			t.Errorf("Add(2, 3) = %d; expected %d", result, expected)
		}
	}
*/
func TestFolders(t *testing.T) {
	dat, _ := d.GetAllUserDataFolders()
	fmt.Println(dat[0].All())
	fmt.Println(dat)
}

func TestAll(t *testing.T) {
	partitions := d.GetNonMountedPartitions()
	users, err := d.GetAllUserDataFolders()
	if err == nil {
		for _, user := range users {
			for _, folder := range user.All() {
				partitions = append(partitions, folder)
			}
		}
	}
	for _, i := range partitions {
		fmt.Println(i)
	}
}

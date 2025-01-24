package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Test for isValidEmail function
func TestIsValidEmail(t *testing.T) {
	testCases := []struct {
		email    string
		expected bool
	}{
		{"valid.email@example.com", true},
		{"invalid.email@com", false},
		{"another.valid-email@example.co.uk", true},
		{"invalid-email@", false},
		{"@invalid.com", false},
	}

	for _, testCase := range testCases {
		result := isValidEmail(testCase.email)
		if result != testCase.expected {
			t.Errorf("Failed for email: %s. Expected: %t, Got: %t", testCase.email, testCase.expected, result)
		}
	}
}

type TestWhale struct {
	Name            string  `json:"name"`
	DietType        string  `json:"dietType"`
	Size            float64 `json:"size"`
	Habitat         string  `json:"habitat"`
	PopulationCount int     `json:"populationCount"`
}

func TestCRUDWhale(t *testing.T) {
	setupMongoDB()

	ts := httptest.NewServer(http.HandlerFunc(createWhaleHandler))
	defer ts.Close()

	whale := TestWhale{
		Name:            "Blue Whale",
		DietType:        "Carnivore",
		Size:            30.0,
		Habitat:         "Ocean",
		PopulationCount: 10000,
	}
	whaleData, _ := json.Marshal(whale)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewBuffer(whaleData))
	if err != nil {
		t.Fatalf("Failed to create whale: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status code 201, got %d", resp.StatusCode)
	}
}

func TestFilterAndSortWhales(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(filterWhalesHandler))
	defer ts.Close()

	// Test filter whales by diet type
	resp, err := http.Get(ts.URL + "?dietType=Carnivore")
	if err != nil {
		t.Fatalf("Failed to fetch filtered whales: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	ts = httptest.NewServer(http.HandlerFunc(sortWhalesHandler))
	defer ts.Close()

	// Test sort whales by size in descending order
	resp, err = http.Get(ts.URL + "?sortBy=size&order=desc")
	if err != nil {
		t.Fatalf("Failed to fetch sorted whales: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}
}
func setupMongoDB() {
	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	usersCollection = client.Database("test_db").Collection("users")
}

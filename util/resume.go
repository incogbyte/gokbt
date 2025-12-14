package util

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

type ResumeState struct {
	Command    string            `json:"command"`
	File       string            `json:"file"`
	Processed  map[string]bool   `json:"processed"`
	LastLine   int               `json:"last_line"`
	Successes  []string          `json:"successes"`
	mu         sync.Mutex
	filename   string
	dirty      bool
}

func NewResumeState(filename string, command string, inputFile string) *ResumeState {
	return &ResumeState{
		Command:   command,
		File:      inputFile,
		Processed: make(map[string]bool),
		Successes: []string{},
		filename:  filename,
	}
}

func LoadResumeState(filename string) (*ResumeState, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var state ResumeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	state.filename = filename
	return &state, nil
}

func (r *ResumeState) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if !r.dirty {
		return nil
	}
	
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	r.dirty = false
	return os.WriteFile(r.filename, data, 0644)
}

func (r *ResumeState) MarkProcessed(item string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Processed[item] = true
	r.dirty = true
}

func (r *ResumeState) IsProcessed(item string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Processed[item]
}

func (r *ResumeState) AddSuccess(item string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Successes = append(r.Successes, item)
	r.dirty = true
}

func (r *ResumeState) SetLastLine(line int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.LastLine = line
	r.dirty = true
}

func (r *ResumeState) Delete() error {
	return os.Remove(r.filename)
}

type ValidOutputFile struct {
	file *os.File
	mu   sync.Mutex
}

func NewValidOutputFile(filename string) (*ValidOutputFile, error) {
	if filename == "" {
		return nil, nil
	}
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return &ValidOutputFile{file: f}, nil
}

func (v *ValidOutputFile) Write(result string) error {
	if v == nil || v.file == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.file.WriteString(result + "\n")
	return err
}

func (v *ValidOutputFile) Close() error {
	if v == nil || v.file == nil {
		return nil
	}
	return v.file.Close()
}

func CountLines(filename string) (int64, error) {
	if filename == "-" {
		return 0, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	
	var count int64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}


package snapshot

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math"
	"testing"
)

func Test_V1EncoderCreate(t *testing.T) {
	// Original data to compress and write.
	data := []byte("test data")

	// Create new V1 snapshot.
	snap := NewV1Encoder(data)

	// Write snapshot to buffer.
	var buf bytes.Buffer
	n, err := snap.WriteTo(&buf)
	if err != nil {
		t.Fatalf("failed to write snapshot: %v", err)
	}

	// Read back the data from the buffer.
	r := bytes.NewReader(buf.Bytes())

	// Read and verify the compression flag.
	var flag uint64
	if err := binary.Read(r, binary.LittleEndian, &flag); err != nil {
		t.Fatalf("failed to read compression flag: %v", err)
	}
	if flag != math.MaxUint64 {
		t.Fatalf("compression flag is wrong")
	}

	// Read and verify the size of the compressed data.
	var size uint64
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		t.Fatalf("failed to read compressed data size: %v", err)
	}
	if size != uint64(n-16) { // Subtract 16 bytes for the flag and size.
		t.Fatalf("unexpected compressed data size; got %v, want %v", size, uint64(n-16))
	}

	// Read and verify the compressed data.
	cdata := make([]byte, size)
	if _, err := io.ReadFull(r, cdata); err != nil {
		t.Fatalf("failed to read compressed data: %v", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(cdata))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	decData, err := ioutil.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to decompress data: %v", err)
	}
	if !bytes.Equal(decData, data) {
		t.Fatalf("unexpected decompressed data; got %q, want %q", decData, data)
	}
}

func Test_V1EncoderNilSlice(t *testing.T) {
	v := NewV1Encoder(nil)

	var buf bytes.Buffer
	n, err := v.WriteTo(&buf)
	if err != nil {
		t.Fatalf("failed to write to buffer: %v", err)
	}

	if n != 16 { // 16 bytes for the flag and size.
		t.Errorf("unexpected number of bytes written; got %d, want %d", n, 16)
	}

	r := bytes.NewReader(buf.Bytes())

	// Read and verify the compression flag.
	var flag uint64
	if err := binary.Read(r, binary.LittleEndian, &flag); err != nil {
		t.Fatalf("failed to read compression flag: %v", err)
	}
	if flag != math.MaxUint64 {
		t.Errorf("unexpected compression flag")
	}

	// Read and verify the size of the compressed data.
	var size uint64
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		t.Fatalf("failed to read compressed data size: %v", err)
	}
	if size != 0 { // The compressed data size should be 0.
		t.Errorf("unexpected compressed data size; got %d, want %d", size, 0)
	}

	// Verify that there is no more data.
	if r.Len() != 0 {
		t.Errorf("unexpected remaining data; got %d, want %d", r.Len(), 0)
	}
}

func TestV1Decoder(t *testing.T) {
	// Create a test data.
	data := []byte("This is a test data.")

	// Create a new V1Encoder and compress the data.
	encoder := NewV1Encoder(data)
	var encBuf bytes.Buffer
	_, err := encoder.WriteTo(&encBuf)
	if err != nil {
		t.Fatalf("Failed to write to encoder: %v", err)
	}

	// Create a new V1Decoder and decode the compressed data.
	decoder := NewV1Decoder(&encBuf)
	var decBuf bytes.Buffer
	_, err = decoder.WriteTo(&decBuf)
	if err != nil {
		t.Fatalf("Failed to write to decoder: %v", err)
	}

	// The original and decoded data should match.
	if !bytes.Equal(data, decBuf.Bytes()) {
		t.Fatalf("Data mismatch; got %s, want %s", decBuf.Bytes(), data)
	}
}

# WASM

### Build Web assembly

This step will compile `crypto/wasm/wasm.go` to `tss.wasm`.

```
$ make wasm
```

### Build proto for Golang

```
$ make protobuf
```

### Build proto for JavaScript

The protobuf file for JavaScript will be used in `index.js`.

```
$ make protobuf
```

### Run sample

If this is the first time, you need to install some node packages.

```
$ npm install
```

Then, run the node sample program.
```
$ make wasm-test
```

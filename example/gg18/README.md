# TSS example

This program demonstrates a simple TSS example by using [go-libp2p](https://github.com/libp2p/go-libp2p). It contains 3 sub-commands which are

1. `dkg`: generate shares
2. `signer`: sign a message
3. `reshare`: refresh shares

## Configuration
### Common

All commands have their own configurations which are located in `dkg/` folder, `signer/` folder, and `reshare/` folder respectively. These config files are [YAML](https://yaml.org/) format and they should contain the required input that commands need.

There are some common inputs.

1. `port`: Port that this node will listen for.
2. `peers`: A list of peers (including port and ID) that this node will try to connect to.
3. `identity`: The base64-encoded private key of this node used as an identity during p2p connection.

### DKG

#### Run

Please run each command in its own terminal.

```
go run ./example/gg18/main.go dkg --config ./example/gg18/dkg/node-1.yaml
```

```
go run ./example/gg18/main.go dkg --config ./example/gg18/dkg/node-2.yaml
```

```
go run ./example/gg18/main.go dkg --config ./example/gg18/dkg/node-3.yaml
```

#### Input

Besides the common inputs, DKG will need another two inputs.

1. `rank`: The rank of this node during HTSS algorithm.
2. `threshold`: The threshold that needed to generate a valid signature.

For example, in file `dkg/node-1.yaml`, a complete DKG configuration is shown below.

```yaml
port: 10001
identity: <base64 private key>
peers:
  - id: QmUmf4xxZYPS8vXzz2uAAaNpogxEugYpmPDnnu9saon4c5
    port: 10002
  - id: QmaLCt3WyUrbjqKtwKNaSdKiQnyhwGJyFsLHxhnsuQ1XRB
    port: 10003
rank: 0
threshold: 3
```

#### Output

After the process finished, the results will be printed in the console:

1. `share`: The respective share of the node. The value of share in these output files must be different.
2. `pubkey`: The public key. The value of public key in these output files must be the same.
3. `bks`: The Birkhoff parameter of all nodes. Each Birkhoff parameter contains x coordinate and the rank.

The results can then be used in the `signer` or `reshare`

### Signer

#### Run

Please run each command in its own terminal.

```
go run ./example/gg18/main.go signer --config ./example/gg18/signer/node-1.yaml
```

```
go run ./example/gg18/main.go signer --config ./example/gg18/signer/node-2.yaml
```

```
go run ./example/gg18/main.go signer --config ./example/gg18/signer/node-3.yaml
```

#### Input

Besides the common inputs, signer will need another three inputs.

1. `share`: The respective share generated from DKG.
2. `pubkey`: The public key generated from DKG.
3. `bks`: The Birkhoff parameter of all peers.
4. `msg`: The message to be signed.

> Note that `msg` for all participants must be the same. If the value of message is different, signing process will fail. Most of the time, this message will be a cryptographic transaction. And the transaction might be created from one party. Therefore, practically, before signing, another information exchange for the raw transaction might be required.

For example, in file `signer/node-1.yaml`, a complete signer configuration is shown below.

```yaml
port: 10001
identity: <base64 private key>
peers:
  - id: QmUmf4xxZYPS8vXzz2uAAaNpogxEugYpmPDnnu9saon4c5
    port: 10002
  - id: QmaLCt3WyUrbjqKtwKNaSdKiQnyhwGJyFsLHxhnsuQ1XRB
    port: 10003
threshold: 3
share: "43644913548181645287879790784662096225860189154158098069609137977414752534059"
pubkey:
  x: "27882792200082538193538545551774104988722526825580413993287021541130525522506"
  y: "47518155860714482173853669036936666461812430911736775716259581894684305008163"
bks:
  QmUmf4xxZYPS8vXzz2uAAaNpogxEugYpmPDnnu9saon4c5:
    x: "96782832843895239967815563282248691718063628467743259362629465575967588658871"
    rank: 0
  QmYhhVHmpU5X62Qxs3C7JsN1mmbqG435vCbon2qH75C7EW:
    x: "84789029780423094029780127795122590534572908912310560758172674231895736569017"
    rank: 0
  QmaLCt3WyUrbjqKtwKNaSdKiQnyhwGJyFsLHxhnsuQ1XRB:
    x: "71607254965713618201500545083308585159927785132409522113529861536051048547771"
    rank: 0
msg: "hello tss"
```

> Note: All signer config files have already contained executable configurations. However, you could also try to copy the results from DKG/reshare results and overwrite the configurations.

#### Output

After the process finished, the results will be printed in the console. Each result contains a valid signature and all signatures  should be the same (both `r` and `s`).

### Reshare

#### Run

Please run each command in its own terminal.

```
go run ./example/gg18/main.go reshare --config ./example/gg18/reshare/node-1.yaml
```

```
go run ./example/gg18/main.go reshare --config ./example/gg18/reshare/node-2.yaml
```

```
go run ./example/gg18/main.go reshare --config ./example/gg18/reshare/node-3.yaml
```

#### Input

Besides the common inputs, reshare will need another four inputs.

1. `threshold`: The threshold that determined when DKG.
2. `share`: The respective share generated from DKG.
3. `pubkey`: The public key generated from DKG.
4. `bks`: The Birkhoff parameter of all peers.

For example, in file `reshare/node-1.yaml`, a complete reshare configuration is show below.

```yaml
port: 10001
identity: <base64 private key>
peers:
  - id: QmUmf4xxZYPS8vXzz2uAAaNpogxEugYpmPDnnu9saon4c5
    port: 10002
  - id: QmaLCt3WyUrbjqKtwKNaSdKiQnyhwGJyFsLHxhnsuQ1XRB
    port: 10003
threshold: 3
share: "43644913548181645287879790784662096225860189154158098069609137977414752534059"
pubkey:
  x: "27882792200082538193538545551774104988722526825580413993287021541130525522506"
  y: "47518155860714482173853669036936666461812430911736775716259581894684305008163"
bks:
  QmUmf4xxZYPS8vXzz2uAAaNpogxEugYpmPDnnu9saon4c5:
    x: "96782832843895239967815563282248691718063628467743259362629465575967588658871"
    rank: 0
  QmYhhVHmpU5X62Qxs3C7JsN1mmbqG435vCbon2qH75C7EW:
    x: "84789029780423094029780127795122590534572908912310560758172674231895736569017"
    rank: 0
  QmaLCt3WyUrbjqKtwKNaSdKiQnyhwGJyFsLHxhnsuQ1XRB:
    x: "71607254965713618201500545083308585159927785132409522113529861536051048547771"
    rank: 0
```

> Note: All reshare config files have already contained executable configurations. However, you could also try to copy the results from DKG result files and overwrite the configurations (e.g from `dkg/node-1.yaml` to `reshare/node-1.yaml`).

#### Output

After the process finished, the results will be printed in the console. Each result contains a new share. The value of the new shares should be different from the old ones and should be different from each other as well.

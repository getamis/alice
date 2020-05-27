# TSS example

This program demonstrates a simple TSS example by using [go-libp2p](https://github.com/libp2p/go-libp2p). It contains 3 sub-commands which are

1. `dkg`: generate shares
2. `signer`: sign a message
3. `reshare`: refresh shares

## Configuration
### Common

All commands have their own configurations which are located in `dkg/` folder, `signer/` folder, and `reshare/` folder respectively. These config files are [YAML](https://yaml.org/) format and they should contain the required input that commands need.

Beyond all commands, there are some common inputs.

1. `port`: Port that this node will listen for.
2. `peers`: A list of peer's ports that this node will try to connect to.

### DKG
#### Input

Besides the common inputs, DKG will need another two inputs.

1. `rank`: The rank of this node during HTSS algorithm.
2. `threshold`: The threshold that needed to generate a valid signature.

For example, in file `dkg/id-10001-input.yaml`, a complete DKG configuration is shown below.

```yaml
port: 10001
rank: 0
threshold: 3
peers:
  - 10002
  - 10003
```

#### Output

After DKG, there should be 3 new output files created in `example/dkg` folder. In each file, it should contain three elements.

1. `share`: The respective share of the node. The value of share in these output files must be different.
2. `pubkey`: The public key. The value of public key in these output files must be the same.
3. `bks`: The Birkhoff parameter of all nodes. Each Birkhoff parameter contains x coordinate and the rank.

### Signer
#### Input

Besides the common inputs, signer will need another three inputs.

1. `share`: The respective share generated from DKG.
2. `pubkey`: The public key generated from DKG.
3. `bks`: The Birkhoff parameter of all peers.
4. `msg`: The message to be signed.

> Note that `msg` for all participants must be the same. If the value of message is different, signing process will fail. Most of the time, this message will be a cryptographic transaction. And the transaction might be created from one party. Therefore, practically, before signing, another information exchange for the raw transaction might be required.

For example, in file `signer/id-10001-input.yaml`, a complete signer configuration is show below.

```yaml
port: 10001
peers:
  - 10002
  - 10003
share: "101420976052030730685561069719911392914434824397492564228646546319061446487458"
pubkey:
  x: "47143094896967716337843669989860432144962851204356940818421228324575441222601"
  y: "23336444423741848139737884993242101588835841992098573257496438799812162311375"
bks:
  id-10001:
    x: "60804574656888231803750758362258552766945294870709728961250573287297336332061"
    rank: 0
  id-10002:
    x: "69585139089653513675598669644888535871994689088749672680139122876344694547847"
    rank: 0
  id-10003:
    x: "42617894318064911861435689891609248836936982258022075394462053252726961520252"
    rank: 0
msg: "hello tss"
```

> Note: All signer config files have already contained executable configurations. However, you could also try to copy the results from DKG/reshare result files and overwrite the configurations (e.g from `dkg/id-10001-output.yaml` to `signer/id-10001-input.yaml`).

#### Output

After signing, there should be 3 new output files created in `example/signer` folder. In each file, it should contain a valid signature. And the value of the signature (both `r` and `s`) in these output files must be the same.

### Reshare
#### Input

Besides the common inputs, reshare will need another four inputs.

1. `threshold`: The threshold that determined when DKG.
2. `share`: The respective share generated from DKG.
3. `pubkey`: The public key generated from DKG.
4. `bks`: The Birkhoff parameter of all peers.

For example, in file `reahre/id-10001-input.yaml`, a complete reshare configuration is show below.

```yaml
port: 10001
threshold: 3
peers:
  - 10002
  - 10003
share: "101420976052030730685561069719911392914434824397492564228646546319061446487458"
pubkey:
  x: "47143094896967716337843669989860432144962851204356940818421228324575441222601"
  y: "23336444423741848139737884993242101588835841992098573257496438799812162311375"
bks:
  id-10001:
    x: "60804574656888231803750758362258552766945294870709728961250573287297336332061"
    rank: 0
  id-10002:
    x: "69585139089653513675598669644888535871994689088749672680139122876344694547847"
    rank: 0
  id-10003:
    x: "42617894318064911861435689891609248836936982258022075394462053252726961520252"
    rank: 0
```

> Note: All reshare config files have already contained executable configurations. However, you could also try to copy the results from DKG result files and overwrite the configurations (e.g from `dkg/id-10001-output.yaml` to `reshare/id-10001-input.yaml`).

#### Output

After reshare, there should be 3 new output files created in `example/reshare` folder. In each file, it should contain a new share. The value of new share must be different with the old one and each share in the output files must be different as well.

### Comparison

In conclusion, every execution will need to consume a input configuration and if the execution is successful, an output result file will be generated. The input and output file of one process will be places at the same folder. The below table shows the location of every input config file and output result file.

| Location | DKG | signer | reshare |
|---|---|---|---|
| config | `dkg/id-{peer_port}-input.yaml` | `signer/id-{peer_port}-input.yaml` | `reshare/id-{peer_port}-input.yaml` |
| result | `dkg/id-{peer_port}-output.yaml` | `signer/id-{peer_port}-input.yaml` | `reshare/id-{peer_port}-input.yaml` |

## Execution

In this example, we try to simulate the real situation of TSS algorithm. You need to create different processes on different environments (3 terminals in this example). After each process is executed, the node will be started and it will be blocked until it connects to all the peers. Therefore, you will see the following warnings when a new process started.

```
WARN [04-15|11:07:07.592|peer/node.go:141] Failed to connect to peer                err="..."
WARN [04-15|11:07:07.592|peer/pm.go:89]    Failed to connect to peer                to=... err="..."
WARN [04-15|11:07:07.592|peer/node.go:141] Failed to connect to peer                err="..."
WARN [04-15|11:07:07.592|peer/pm.go:89]    Failed to connect to peer                to=... err="..."
```

These warnings are normal since it requires all peers connected before the algorithm execution. After every node is started and they are connected with each other, you will see the following debug messages and the process will continue.

```
DEBUG[04-15|11:07:13.600|peer/pm.go:93]    Successfully connect to peer             to=...
DEBUG[04-15|11:07:16.602|peer/pm.go:93]    Successfully connect to peer             to=...
```

## Build

At project root directory, you could use the following command to build an executable binary in `example/` folder.

```sh
> make tss-example
```

## Usage

Here, you could try to run the example on your local machine. After the binary was built, you could go to `/example` folder and open three terminals.

### DKG

First, run 3 hosts on different terminals. Each node will need to consume a config file (e.g `dkg/id-10001-input.yaml`) by using `--config` or `-c` to specify the path of the config file. These 3 nodes will try to connect to each other. Once it connects to a peer, it will send the peer message out. After the peer messages are fully transmitted, each node will try to get the result and write it to the respective result file.

On node A, 
```sh
> ./example dkg --config dkg/id-10001-input.yaml
```

On node B,
```sh
> ./example dkg --config dkg/id-10002-input.yaml
```

On node C,
```sh
> ./example dkg --config dkg/id-10003-input.yaml
```

After DKG, there should be 3 new output files created in `example/dkg` folder.

### Signer

When signing, each node will need to consume their own config file (e.g `signer/id-10001-input.yaml`) by using `--config` or `-c` to specify the path of the config file. Once it connects to a peer, it will send the public key message out. After the public key messages are fully transmitted, each node will try to get the result and write it to the respective result file.

On node A,
```sh
> ./example signer --config signer/id-10001-input.yaml
```

On node B,
```sh
> ./example signer --config signer/id-10002-input.yaml
```

On node C,
```sh
> ./example signer --config signer/id-10003-input.yaml
```

After signing, there should be 3 new output files created in `example/signer` folder.

### Reshare

When reshare, all peers associated with DKG should be involved. Again, each node will need to consume their own config file (e.g `reshare/id-10001-input.yaml`) by using `--config` or `-c` to specify the path of the config file. Once it connects to a peer, it will send the commit message out. After the commit messages are fully transmitted, each node will try to get the result and write it to the respective result file.

On node A,
```sh
> ./example reshare --config reshare/id-10001-input.yaml
```

On node B,
```sh
> ./example reshare --config reshare/id-10002-input.yaml
```

On node C,
```sh
> ./example reshare --config reshare/id-10003-input.yaml
```

After reshare, there should be 3 new output files created in `example/reshare` folder.

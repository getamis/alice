require("./wasm_exec.js");
const WebSocket = require('ws');
const reqMessage = require('./message/message_pb');

async function wasm() {
    const url = 'wss://tmp-dev-console.raicrypt.org/htss/dkg';
    const ws = new WebSocket(url);

    send = function (data) {
        ws.send(data);
    }

    ws.on('message', function incoming(msg) {
        handleDKGData(Buffer.from(msg).toString('hex'));
    });

    ws.on('close', function close() {
        console.log('The connection has been closed successfully.');
    })

    const go = new Go();
    const result = await WebAssembly.instantiate(fs.readFileSync("tss.wasm"), go.importObject);
    go.run(result.instance);

    // TODO: need init message

    // self id
    const selfID = "0"
    // server peer id
    const peerID1 = "1"
    const password = "my-secret-pw"
    await newDKG(selfID, [peerID1], password, (targetPeerID, message) => {
        send(Uint8Array.from(Buffer.from(message, 'hex')));
    }, (err, result) => {
        if (err) {
            console.error(err);
            return;
        }

        console.log(result);
    });
}
wasm();

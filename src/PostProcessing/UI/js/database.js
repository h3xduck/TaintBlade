var dbFileElm = document.getElementById('dbfile');

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
}

function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2);
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

const worker = new Worker("http://localhost:8000/js/sqljs/worker.sql-wasm.js");
worker.onmessage = () => {
    console.log("Database opened");
    worker.onmessage = event => {
        console.log(event.data); // The result of the query
    };

    /*worker.postMessage({
        id: 2,
        action: "exec",
        sql: "SELECT * FROM color_trasformation",
        params: {}
    });*/
};

worker.onerror = e => console.log("Worker error: ", e);

dbFileElm.onchange = function () {
    console.log("Selected new database")
    var f = dbFileElm.files[0];
    var r = new FileReader();
    r.onload = function () {
        worker.postMessage({
            action: 'open',
            buffer: r.result
        });


        worker.postMessage({
            id: 2,
            action: "exec",
            sql: "SELECT * FROM color_transformation",
            params: {}
        });
    }
    r.readAsArrayBuffer(f);
}

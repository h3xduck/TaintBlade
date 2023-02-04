var dbFileElm = $('#dbfile');
var outputBoxElm = $('#outputBox');



///////////////////// DATABASE STUFF /////////////////////
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

//Loads the database and shows function calls once 
dbFileElm.change(function () {
    console.log("Selected new database")
    var f = dbFileElm.prop('files')[0];
    var r = new FileReader();
    r.onload = function () {
        worker.postMessage({
            action: 'open',
            buffer: r.result
        });


        /*worker.postMessage({
            id: 2,
            action: "exec",
            sql: "SELECT * FROM color_transformation",
            params: {}
        });*/

        outputBoxElm.html("Database loaded")
    }
    r.readAsArrayBuffer(f);
});

// Run a command in the database, get a table with all rows and columns
function executeGetTableResults(commands) {
    worker.onmessage = function (event) {
        console.log("Received message");
        var results = event.data.results;
        console.log(results);
        if (!results) {
            console.log("ERROR receiving worker results: " + event.data.error);
            return;
        }

        outputBoxElm.empty();
        for (var i = 0; i < results.length; i++) {
            outputBoxElm.append(tableCreate(results[i].columns, results[i].values));
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}


///////////////////// UI STUFF /////////////////////

// Create an HTML table
var tableCreate = function () {
    function valconcat(vals, tagName) {
        if (vals.length === 0) return '';
        var open = '<' + tagName + '>', close = '</' + tagName + '>';
        return open + vals.join(close + open) + close;
    }

    return function (columns, values) {
        var tbl = document.createElement('table');
        tbl.className = "results-table"
        var html = '<thead>' + valconcat(columns, 'th') + '</thead>';
        var rows = values.map(function (v) { return valconcat(v, 'td'); });
        html += '<tbody>' + valconcat(rows, 'tr') + '</tbody>';
        tbl.innerHTML = html;
        return tbl;
    }
}();



///////////////////// ELEMENT EVENTS /////////////////////
function showAllFunctions(elem) {
    executeGetTableResults(
        "SELECT * FROM function_calls"
    );
}

function showColorChanged(elem) {
    executeGetTableResults(
        "SELECT color, inst_address, mem_address, dll_from, dll_to, func_from, func_to "+
        "FROM memory_colors AS m " +
        "LEFT JOIN function_calls AS f " +
        "ON m.func_index = f.appearance "+
        "ORDER BY func_index"
    );
}


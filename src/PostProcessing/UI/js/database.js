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
function executeGetFullTableResults(commands) {
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
            outputBoxElm.append(tableCreateGeneral(results[i].columns, results[i].values));
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}

// Run a command in the database, get a table with function calls
// For function_calls table
function executeFormatFunctionCalls(commands) {
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
            outputBoxElm.append(tableCreateFormatFunctionCalls(results[i].columns, results[i].values));
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}

// Run a command in the database, get args corresponding to a function call given an id
// For the dropdown at the functions table
function executeFormatFunctionArguments(commands, parentRow) {
    worker.onmessage = function (event) {
        console.log("Received message");
        var results = event.data.results;
        console.log(results);
        if (!results) {
            console.log("ERROR receiving worker results: " + event.data.error);
            return;
        }

        for (var i = 0; i < results.length; i++) {
            parentRow.after('<tr><td>');
            parentRow.next().append(tableCreateGeneral(results[i].columns, results[i].values));
            parentRow.next().append('</td></tr>');
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}

///////////////////// UI STUFF /////////////////////

// Create an HTML table, all columns shown
var tableCreateGeneral = function () {
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

// Create an HTML table, args contained in dropdown
var tableCreateFormatFunctionCalls = function () {
    function valconcat(vals, tagName) {
        if (vals.length === 0) return '';
        var open = '<' + tagName + '>', close = '</' + tagName + '>';
        return open + vals.join(close + open) + close;
    }

    function valConcatWithPkey(vals, tagName) {
        if (vals.length === 0) return '';
        var open = '<' + tagName + '>', close = '</' + tagName + '>';
        
        //The one with appearance is hidden
        var res =  '<' + tagName + ' class="pkey">' + vals[0] + close +
            open + vals[1] + close + open + vals[2] + close + open + vals[3] + close +
            open + vals[4] + close + open + vals[5] + close + open + vals[6] + close;
        return res;
    }

    return function (columns, values) {
        var tbl = document.createElement('table');
        tbl.className = "results-table";
        var html = '<thead>' +
            '<th>Action</th>' +
            valConcatWithPkey(columns, 'th') + '</thead>';
        var rows = values.map(function (v) {
            return '<td><button type="button" class="btn btn-success exploder" onclick="exploderClick(this)">' +
                ' <span class="fas fa-plus-square"></span>' +
                '</button ></td >' + valConcatWithPkey(v, 'td');
        });
        html += '<tbody>' + valconcat(rows, 'tr') +'</tbody>';
        tbl.innerHTML = html;
        return tbl;
    }
}();



///////////////////// ELEMENT EVENTS /////////////////////
function showAllFunctions(elem) {
    executeFormatFunctionCalls(
        "SELECT appearance, dll_from, func_from, memaddr_from, dll_to, func_to, memaddr_to " +
        "FROM function_calls"
    );
}

function showColorChanged(elem) {
    executeGetFullTableResults(
        "SELECT color, inst_address, mem_address, dll_from, dll_to, func_from, func_to "+
        "FROM memory_colors AS m " +
        "LEFT JOIN function_calls AS f " +
        "ON m.func_index = f.appearance "+
        "ORDER BY func_index"
    );
}

function exploderClick(elem) {
    //Check whether to show or hide arguments table
    var icon = $(elem).children('span').eq(0);
    if (icon.hasClass("fa-plus-square")) {
        //Change the icon to hide element
        var icon = $(elem).children('span').eq(0);
        icon.removeClass("fa-plus-square");
        icon.addClass("fa-minus-square");

        //We generate an additional row where we will show the arguments of the function
        var key = $(elem).parent().parent().find(".pkey").text();
        var parentRow = $(elem).parent().parent();
        executeFormatFunctionArguments(
            "SELECT arg0, arg1, arg2, arg3, arg4, arg5 FROM function_calls " +
            "WHERE appearance=" + key,
            parentRow);

    } else {
        //Change the icon to hide element
        var icon = $(elem).children('span').eq(0);
        icon.removeClass("fa-minus-square");
        icon.addClass("fa-plus-square");

        //We remove the arguments table
        var parentRow = $(elem).parent().parent();
        parentRow.next().remove();
    }

    

    
}
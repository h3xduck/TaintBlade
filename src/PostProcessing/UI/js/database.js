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
            parentRow.after('<tr><td colspan="3"></td></tr>');
            parentRow.next().find('td').append(tableCreateGeneral(results[i].columns, results[i].values));
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}

// Get a table with taint events
// For taint_events table
function executeFormatTaintEvents(commands) {
    worker.onmessage = function (event) {
        console.log("Received request for taint events");
        var results = event.data.results;
        console.log(results);
        if (!results) {
            console.log("ERROR receiving worker results: " + event.data.error);
            return;
        }

        outputBoxElm.empty();
        for (var i = 0; i < results.length; i++) {
            outputBoxElm.append(tableCreateTaintEvents(results[i].columns, results[i].values));
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}

// Get a table with taint event details
// For taint_events table when clicking on + button
function executeFormatTaintDetails(commands) {
    worker.onmessage = function (event) {
        console.log("Received request for taint event details");
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

// Get a table function calls and all taint events
// For the function calls events button
function executeFormatEventsFunctionCalls(commands) {
    worker.onmessage = function (event) {
        console.log("Received request for function calls with events");
        var results = event.data.results;
        console.log(results);
        if (!results) {
            console.log("ERROR receiving worker results: " + event.data.error);
            return;
        }

        outputBoxElm.empty();
        for (var i = 0; i < results.length; i++) {
            outputBoxElm.append(tableCreateFormatEventsFunctionCalls(results[i].columns, results[i].values));
        }
    }
    worker.postMessage({ action: 'exec', sql: commands });
    console.log("Posted message with commands:" + commands);
    outputBoxElm.textContent = "Fetching results...";
}

///////////////////// UTILS ////////////////////////
function getColorFormat(color) {
    switch (color) {
        case "UNDEFINED": //UNDEFINED
            return "undefined-event";
        case "UNTAINT": //UNTAINT
            return "untaint-taint-event";
        case "TAINT": //TAINT
            return "taint-taint-event";
        case "CHANGE": //CHANGE
            return "change-taint-event";
        case "MIX": //MIX
            return "mix-taint-event";
        default:
            return "";
    }
}

function getEventFormat(color) {
    switch (color) {
        case 0: //UNDEFINED
            return "UNDEFINED";
        case 1: //UNTAINT
            return "UNTAINT";
        case 2: //TAINT
            return "TAINT";
        case 3: //CHANGE
            return "CHANGE";
        case 4: //MIX
            return "MIX";
        default:
            return "";
    }
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
            '<th></th>' +
            valConcatWithPkey(columns, 'th') + '</thead>';
        var rows = values.map(function (v) {
            return '<td class="centered-cell"><button type="button" class="btn btn-success exploder" onclick="exploderClickFunctionArgs(this)">' +
                ' <span class="fas fa-plus-square"></span>' +
                '</button ></td >' + valConcatWithPkey(v, 'td');
        });
        html += '<tbody>' + valconcat(rows, 'tr') +'</tbody>';
        tbl.innerHTML = html;
        return tbl;
    }
}();

var tableCreateTaintEvents = function () {
    function valconcat(vals, tagName) {
        if (vals.length === 0) return '';
        var close = '</' + tagName + '>';

        var html = '';
        for (var i = 0; i < vals.length; i++) {
            var open = '<' + tagName + ' class="' + getColorFormat($(vals[i])[1].textContent.split(" ")[0]) + '">'; 
            html += open + vals[i] + close;
        }

        return html;
    }

    function valConcatWithPkey(vals, tagName) {
        if (vals.length === 0) return '';
        var open = '<' + tagName + '>', close = '</' + tagName + '>';

        //The one with appearance is hidden
        //If memAddress==0, means the event is related to a register, only mixes included
        console.log(vals);
        var res;
        var mixColors = "";
        var eventString = getEventFormat(vals[0]);
        var colorMix1 = vals[5];
        var colorMix2 = vals[6];
        if (eventString == "MIX") {
            mixColors = " using {" + colorMix1 + "} and {" + colorMix2 + "}";
        }
        if (vals[3] != 0) {
            res = '<' + tagName + '>' + eventString + " MEM [" + vals[3] + "] with color {" + vals[4] + "}" + mixColors + close +
                '<' + tagName + ' class="pkey">' + vals[1] + close +
                open + vals[2] + close;
        } else {
            var res = '<' + tagName + '>' + eventString + " register byte with color {" + vals[4] + "}" + mixColors + close +
                '<' + tagName + ' class="pkey">' + vals[1] + close +
                open + vals[2] + close;
        }
        
        return res;
    }

    return function (columns, values) {
        var tbl = document.createElement('table');
        tbl.className = "results-table";
        var html = '<thead>' +
            '<th></th><th>EVENT</th><th>INSTRUCTION</th>' + '</thead>';
        var rows = values.map(function (v) {
            return '<td class="centered-cell"><button type="button" class="btn btn-success exploder" onclick="exploderClickEventDetails(this)">' +
                ' <span class="fas fa-plus-square"></span>' +
                '</button ></td >' + valConcatWithPkey(v, 'td');
        });
        html += '<tbody>' + valconcat(rows, 'tr') + '</tbody>';
        tbl.innerHTML = html;
        return tbl;
    }
}();

var tableCreateFormatEventsFunctionCalls = function () {
    function eventButtonArray(event_types) {
        var types_list = event_types.split(',');
        types_list.sort();
        var button_array = "";
        for (const type_elem of types_list) {
            switch (parseInt(type_elem)) {
                case 0: //UNDEFINED
                    button_array += "<button class=\"undefined-event-indicator\"><span></span></button>";
                    break;
                case 1: //UNTAINT
                    button_array += "<button class=\"untaint-event-indicator\"><span></span></button>";
                    break;
                case 2: //TAINT
                    button_array += "<button class=\"taint-event-indicator\"><span></span></button>";
                    break;
                case 3: //CHANGE
                    button_array += "<button class=\"change-event-indicator\"><span></span></button>";
                    break;
                case 4: //MIX
                    button_array += "<button class=\"mix-event-indicator\"><span></span></button>";
                    break;
            }
        }
        return button_array;
    }

    return function (columns, values) {
        var tbl = document.createElement('table');
        tbl.className = "results-table";
        var html = '<thead>' +
            '<th>LOCATION</th><th>EVENTS</th>' + '</thead>';
        /*var rows = values.map(function (v) {
            return valConcatWithPkey(v, 'td');
        });*/

        var rows = "";
        for (var i = 0; i < values.length; i++) {
            var open = '<td>', close = '</td>';
            var index = values[i][0];
            var func_to = values[i][5];
            var dll_to = values[i][6];
            var inst_address = values[i][8];
            var event_types = values[i][7];
            rows += '<tr><td class="pkey">' + index + close +
                open + "[" + inst_address + "] (" + func_to + " : " + dll_to + ")" + close +
                open + eventButtonArray(event_types) + close + '</tr>';
        }

        html += '<tbody>' + rows + '</tbody>';
        console.log(html);
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

function showTaintEvents(elem) {
    executeFormatTaintEvents(
        "SELECT type, func_index, inst_address, mem_address, color, color_mix_1, color_mix_2 FROM taint_events AS t " +
        "LEFT JOIN color_transformation AS c ON t.color = c.derivate_color " +
        "LEFT JOIN function_calls AS f ON t.func_index = f.appearance " +
        "ORDER BY func_index "
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

function exploderClickFunctionArgs(elem) {
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

function exploderClickEventDetails(elem) {
    //Check whether to show or hide details table
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
            "SELECT func_from, dll_from, func_to, dll_to FROM taint_events AS t " +
            "LEFT JOIN function_calls AS f " +
            "ON t.func_index = f.appearance " +
            "WHERE appearance=" + key +
            " LIMIT 1",
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

function showEventsFunctionCalls(elem) {
    executeFormatEventsFunctionCalls(
        "SELECT func_index, memaddr_from, func_from, dll_from, memaddr_to, func_to, dll_to, group_concat(distinct type) AS types, inst_address, mem_address FROM function_calls AS f " +
        "INNER JOIN taint_events AS t ON f.appearance = t.func_index " +
        "GROUP BY f.appearance"
    );
}
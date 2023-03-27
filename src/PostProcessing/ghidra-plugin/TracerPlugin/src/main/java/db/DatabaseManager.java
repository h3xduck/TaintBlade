package db;

import java.sql.*;
import java.util.ArrayList;

import docking.Tool;
import docking.action.DockingAction;
import docking.actions.DockingToolActions;
import taint.TaintEvent;

public class DatabaseManager {
	private Connection connection = null;
	
	public DatabaseManager(String databaseFilename) throws SQLException{
		this.connection = DriverManager.getConnection("jdbc:sqlite:"+databaseFilename);
	}
	
	public ArrayList<TaintEvent> getTaintEvents() throws SQLException {
		ArrayList<TaintEvent> eventList = new ArrayList<TaintEvent>();
		
		Statement statement = this.connection.createStatement();
        ResultSet resultSet = statement.executeQuery(
        		"SELECT type, func_index, inst_address, mem_address, color, color_mix_1, color_mix_2 FROM taint_events AS t " +
		        "LEFT JOIN color_transformation AS c ON t.color = c.derivate_color " +
		        "LEFT JOIN function_calls AS f ON t.func_index = f.appearance " +
		        "ORDER BY func_index "
        		);
        
        while (resultSet.next()) {
            //System.out.println(resultSet.getString("func_index"));
            eventList.add(new TaintEvent(
            		resultSet.getInt("type"), 
            		resultSet.getLong("func_index"),
            		resultSet.getLong("inst_address"),
            		resultSet.getLong("mem_address"),
            		resultSet.getInt("color"),
            		resultSet.getInt("color_mix_1"),
            		resultSet.getInt("color_mix_2")
            ));
        }
		return eventList;
	}
    
	
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.SqlClient;

namespace myWebApplication
{
    
    public class SQLaccess
    {
        //private static String connectionString = "Data Source=.;Initial Catalog=myVulnappDB;Integrated Security=True";
        //private static String connectionString = "Data Source=.\\SQLEXPRESS;Initial Catalog=myVulnappDB;Integrated Security=True";
        private static String connectionString = "Data Source=theoden.ce.chalmers.se;Initial Catalog=myVulnappDB;Integrated Security=False;UID=myvulnapp;PWD=myvulnapp";

        public static String checkUserPass(String username, String password)
        {
            SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();
            
            //SqlCommand sqlc = new SqlCommand("SELECT Record FROM Table_Users WHERE Username=@username AND Password=@password");
            //sqlc.Parameters.AddWithValue("@username", username);
            //sqlc.Parameters.AddWithValue("@password", password);

            SqlCommand sqlc = new SqlCommand("SELECT Record FROM Table_Users WHERE Username='" + username + "' AND Password='" + password + "'");
            sqlc.Connection = conn;
            SqlDataReader sdr = sqlc.ExecuteReader();
            if (sdr.HasRows == false)
            {
                return null; //no user
            }
            else
            {
                sdr.Read();
                return sdr.GetValue(0).ToString();
            }
        }

        public static String GetUserFromID(String ID)
        {
            SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();


            SqlCommand sqlc = new SqlCommand("SELECT Username,Password FROM Table_Users WHERE SessionID=@sessionid");
            sqlc.Parameters.AddWithValue("@sessionid", ID);

            sqlc.Connection = conn;
            SqlDataReader sdr = sqlc.ExecuteReader();
            if (sdr.HasRows == false)
            {
                return null; //no user
            }
            else
            {
                //can only be one if mechanism works as intended, take the first one
                sdr.Read();
                return sdr.GetValue(0).ToString();
            }

        }

        public static String GetRecordFromID(String ID)
        {
            SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();


            SqlCommand sqlc = new SqlCommand("SELECT Record FROM Table_Users WHERE SessionID=@sessionid");
            sqlc.Parameters.AddWithValue("@sessionid", ID);

            sqlc.Connection = conn;
            SqlDataReader sdr = sqlc.ExecuteReader();
            if (sdr.HasRows == false)
            {
                return null; //no user
            }
            else
            {
                //can only be one if mechanism works as intended, take the first one
                sdr.Read();
                return sdr.GetValue(0).ToString();
            }

        }

        public static Boolean InsertComment(String Name, String Comment)
        {
            SqlConnection conn = new SqlConnection(connectionString);
            SqlCommand sqlc = new SqlCommand("INSERT INTO Table_Comments Values(@name,@comment);");
            sqlc.Parameters.AddWithValue("@name", Name);
            sqlc.Parameters.AddWithValue("@comment", Comment);
            
            try
            {
                conn.Open();
                sqlc.Connection = conn;
                sqlc.ExecuteNonQuery();
                return true;
            }
            catch(Exception ex)
            {
                System.Diagnostics.Debug.Write(ex.StackTrace);
                return false;
            }
            
        }

        public static Boolean InsertSessionID(String record, String SessionID)
        {
            SqlConnection conn = new SqlConnection(connectionString);
            SqlCommand sqlc = new SqlCommand("UPDATE Table_Users SET SessionID=@sessionid WHERE Record=@record;");
            sqlc.Parameters.AddWithValue("@sessionid", SessionID);
            sqlc.Parameters.AddWithValue("@record", record);
            try
            {
                conn.Open();
                sqlc.Connection = conn;
                sqlc.ExecuteNonQuery();
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.Write(ex.StackTrace);
                return false;
            }

        }
        
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace myWebApplication
{
    public partial class Uploadfile : System.Web.UI.UserControl
    {

        private string filepath = "C:\\Temp\\cs_lab4\\myWebApplication\\";

        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnUpload_Click(object sender, EventArgs e)
        {
            if (FileUpload.HasFile == true)
            {
                //there is a file, save it to disk

                filepath += FileUpload.FileName;

                FileUpload.SaveAs(filepath);
                lblStatus.Text = "File saved";

            }
            else
            {
                lblStatus.Text = "No File selected";
            }
        }

        protected void btnBack_Click(object sender, EventArgs e)
        {
            Response.Redirect("default.aspx?page=0");
        }
    }
}
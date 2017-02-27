<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="default.aspx.cs" Inherits="myWebApplication._default" %>

<%@ Register src="Buyform.ascx" tagname="Buyform" tagprefix="uc1" %>
<%@ Register src="Thankyou.ascx" tagname="Thankyou" tagprefix="uc2" %>

<%@ Register src="Uploadfile.ascx" tagname="Uploadfile" tagprefix="uc3" %>

<%@ Register src="ViewComments.ascx" tagname="ViewComments" tagprefix="uc4" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Main. You're lucky to be here</title>
    <link href="Styles/Site.css" rel="stylesheet" type="text/css" />
</head>
<body>
    <div class="center" >

    <form id="form1" runat="server">
    
    <div class="top" >
        <br />
        <br />
        <div style="text-align:center;" >
        <a href="Default.aspx?page=0">Home</a>&nbsp;|&nbsp;
        <a href="Default.aspx?page=1">Buy stuff</a>&nbsp;|&nbsp;
        <a href="Default.aspx?page=3">Upload file</a>&nbsp;|&nbsp;
        <a href="Default.aspx?page=4">View Comments</a>
        </div>
    </div>
    <div class="main">
    <div class="left" >
    
    <asp:Panel ID="Panel_Buy" runat="server" Visible="true" >
        <uc1:Buyform ID="Buyform" runat="server" />
    </asp:Panel>
    <asp:Panel ID="Panel_Thankyou" runat="server" Visible = "false" >
        <uc2:Thankyou ID="Thankyou" runat="server" />
    </asp:Panel>
    <asp:Panel ID="Panel_Uploadfile" runat="server" Visible = "false" >
        <uc3:Uploadfile ID="Uploadfile" runat="server" />
    </asp:Panel>
    <asp:Panel ID="Panel_Viewcomments" runat="server" Visible = "false" >
        <uc4:ViewComments ID="ViewComments1" runat="server" />
    </asp:Panel>
    
    </div>
    <div class="right">
    <h3>
            <asp:Label ID="welcome" Style="color:#AAAAAA;" Text="" runat="server" /><br />
            <asp:Label ID="welcome2" Style="color:#AAAAAA;" Text="" runat="server" />
    </h3>
    </div>
    </div>
    <div class="bottom" >
    <asp:Button ID="logout" Text="Logout" runat="server" onclick="logout_Click"  />
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        All things Sonic Death Monkey. Directly stolen from High Fidelity movie. As a tribute of sorts... Like it?&nbsp;&nbsp;
    </div>
    </form>
    </div>
</body>
</html>

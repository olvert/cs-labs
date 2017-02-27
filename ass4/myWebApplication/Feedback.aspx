<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Feedback.aspx.cs" Inherits="myWebApplication.Feedback" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Send feedback</title>
    <link href="Styles/Site.css" rel="stylesheet" type="text/css" />
</head>
<body>
 <div class="center">
 <div class="top">
 </div>
 <div class="main" >
 <div class="left" >
    <form id="form1" runat="server">
    <asp:HiddenField ID="hfield" runat="server"></asp:HiddenField>
    <div>
    <asp:Panel ID="Panel_feedback" runat="server">
        <asp:Label ID="lblFeedback" runat="server" Text="Feeeedback! Here. Now!"></asp:Label>
        <br />
        <asp:TextBox ID="txtFeedback" runat="server" TextMode="MultiLine" Height="72px" 
            Width="222px"></asp:TextBox>    
        <br />
        <br />
        
        <asp:Label ID="lblName" runat="server" Text="Name. Here!"></asp:Label>
        <br />
        <asp:TextBox ID="txtName" runat="server"></asp:TextBox>
        <br />
        <br />
        <asp:Button ID="btnFeedback" runat="server" Text="Send feedback" 
            onclick="btnFeedback_Click" />
    </asp:Panel>

    <asp:Panel ID="Panel_return" runat="server">
        <asp:label ID="lblThanks" runat="server" Text="Thank you for submitting feedback" ></asp:label>
        <br />
        <br />
        <asp:Button ID="btnReturn" runat="server" Text="Return" 
            onclick="btnReturn_Click" />
    </asp:Panel>

    </div>
    </form>
    </div>
    <div class="right">
        <img src="../images/sdm_skull.jpg" height="172px" width="160px" alt="Jb"  />
    </div>
    </div>
    <div class="bottom">
        All things Sonic Death Monkey. Directly stolen from High Fidelity movie. As a tribute of sorts... Like it?&nbsp;&nbsp;
    </div>
    </div>
</body>
</html>

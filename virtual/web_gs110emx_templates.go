package virtual

// web_gs110emx_templates.go carries the raw byte-faithful GS110EMX web-UI
// HTML fragments (data only, no logic), transcribed VERBATIM from
// src/netgear_switch/virtual/web_gs110emx_templates.py at pin 1841111 (the
// captures are tests/fixtures/http/gs110emx_*.html on a real physical unit --
// see webui/testdata/http/gs110emx_*.html for the Go-side copies). Split out
// of web_gs110emx.go for the same reason the Python source is split: these
// are multi-hundred-byte single-line literals that would otherwise drag
// gofmt/lint noise onto the actual render logic.
//
// Raw Go string literals (backtick-delimited): none of this content contains
// a literal backtick (confirmed at transcription time), so no escaping is
// needed anywhere -- every byte between the backticks below, including quote
// and newline characters, is exactly what a real GS110EMX sent.
const (
	gs110emxLogin = `<!DOCTYPE HTML>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<link rel="stylesheet" type="text/css" href="/login.css">
<meta http-equiv="Pragma" content="no-cache">
<title>NETGEAR GS110EMX</title>
<script src="/login.js" type="text/javascript"></script>
<script src="/jquery.md5.js" type="text/javascript"></script>
<script type='text/javascript' language='JavaScript'>
function submitLogin()
{
    encryptPwd();
    document.forms[0].submit();
	return true;
}
function onEnterSub(e)
{
	var whKey;
	
	if (window.event)
	{
		whKey = e.keyCode;
	}
	else if (e.which)
	{
		whKey = e.which;
	}
	
	if(whKey == '13')
	{
		submitLogin();
	}
}
</script>
</head>
<body id="loginBody" onLoad="document.login.Password.focus();">
<form name="login" method="post" onSubmit="return false;"
					action="/redirect.html" autocomplete="off">
<input type="hidden" id="submitPwd" name="LoginPassword" value="">
<div class="main_div">
	<div class="second_div">
		<div id="main_r_1">
			<div class="main_top_div">
				<table style="width: 100%;" cellpadding="0" cellspacing="0">
					<tr>
						<td style="width: 100%; vertical-align: top;" colspan="2">
							<table id="Table3" style="width: 100%;">						
								<tr>
									<td class="logoNetGear">
									</td>
									<td id="productImg" class="logoDeviceImage" style="display: block;"></td>
								</tr>
							</table>
						</td>
					</tr>
					<tr>
						<td colspan="2">
							<div id="titleDescription">
								<span>GS110EMX - 8-Port Gigabit Ethernet Smart Managed Plus Switch with 2-Port 10G/Multi-Gig Uplinks</span>
							</div>
						</td>
					</tr>
				</table>
			</div>
		</div>
		<div id="main_r_2">
			<div class="loginTable">
				<table id="loginForm" cellspacing="0" cellpadding="0" border="0">
					<tr>
						<td style="padding-bottom: 4px;" colspan="3">
							<table class="subSectionTab" cellspacing="0" cellpadding="0" type="table">
								<tr>
									<td class="subSectionTabTopLeft spacer1Px bluelink font14BoldBlue" colspan="2"> Login </td>
									<td class="subSectionTabTopRight spacer99Percent">
										<a>
										<img width="11" height="11" style="cursor:pointer" onclick="newWindow('/help.html#login','login','400','400')" src="/help_icon.png" title="Click for help">
										</a>
									</td>
								</tr>
							</table>
						</td>
					</tr>
					<tr>
						<td class="subSectionBody"></td>
						<td class="globalLoginTable Spacer100Percent" width="100%" style="padding:0">
							<table class="subSectionTab" cellspacing="0" cellpadding="0" style="width: 404px; margin: 30px 23px 17px;">
								<tr>
									<td class="font13" nowrap="" style="padding-right:20px;padding-top:0;">Password</td>
									<td class="black10" nowrap="" align="left" style="width:100%;">
										<input id="Password" class="InputTextEnabled" type="password" value="" size="32" maxlength="20" tabindex="2" onkeypress="onEnterSub(event);" autocomplete="off">
									</td>
								</tr>
								<tr>
									<td style="padding-right: 83px;"> </td>
									<td class="errPasswdMsg" colspan="2">
									<p id="login_err_msg" style="margin:0;"></p>
									</td>
								</tr>
								<tr>
									<td align="right" style="padding-top:0px; padding-right:0px;" colspan="2">
									<input id="button_Login" type="button" value="Login" style="cursor:pointer" onclick="submitLogin();">
									</td>
								</tr>
							</table>
						</td>
						<td class="subSectionBody"> </td>
					</tr>
				</table>
			</div>
		</div>
		<div id="main_r_3">
			<div class="Copyright" valign="bottom" style="padding:0">
				<div id="copyrightLogin" style="width: 500px;">Copyright &copy; NETGEAR, Inc. All rights reserved</div>
				<img id="footImg" width="276" height="139" border="0" src="/Footer_Facet.png">
			</div>
		</div>
		<div>
		<input type="hidden" id='rand' value="__RAND__" disabled>
		</div>
	</div>
</div>
</form>
</body>
</html>
`

	gs110emxRedirect = `<html>
<head>
<script>
function loadHomePage()
{
	document.forms[0].submit();
}
</script>
</head>
<body onload="loadHomePage()">
<form method="post" action="/homepage.html">
<input type="hidden" name="Gambit" value="__GAMBIT__">
</form>
</body>
</html>
`

	gs110emxSysinfo = `<!DOCTYPE HTML>
<html>
<HEAD>
<link rel="stylesheet" href="/style.css" type="text/css">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<title>Switch Information</title>
<script src="/frame.js" type="text/javascript"></script>
<script src="/function.js" type="text/javascript"></script>
<script src="/script.js" type="text/javascript"></script>
<script type='text/javascript' language='JavaScript'>
function selectOptions()
{
  var dhcp_mode = document.getElementById('dhcpmode');
  selectObj();
  if(dhcp_mode.value === "2"){
	document.forms[0].elements.refresh.disabled = true;
	document.forms[0].elements.IP_ADDRESS.disabled = false;
	document.forms[0].elements.SUBNET_MASK.disabled = false;
	document.forms[0].elements.GATEWAY_ADDRESS.disabled = false;
  }
  else if(dhcp_mode.value === "1"){
	document.forms[0].elements.refresh.disabled = false;
	document.forms[0].elements.IP_ADDRESS.disabled = true;
	document.forms[0].elements.SUBNET_MASK.disabled = true;
	document.forms[0].elements.GATEWAY_ADDRESS.disabled = true;
  }
  dhcp_mode.setAttribute("data-value", dhcp_mode.value);
}
function dhcpModeChange()
{
  var dhcp_mode = document.getElementById('dhcpmode');
  if (dhcp_mode.options[0].selected == true)
  {
    document.forms[0].elements.refresh.disabled = true;
    document.forms[0].elements.IP_ADDRESS.disabled = false;
    document.forms[0].elements.SUBNET_MASK.disabled = false;
    document.forms[0].elements.GATEWAY_ADDRESS.disabled = false;
  }
  else if (dhcp_mode.options[1].selected == true)
  {
    document.forms[0].elements.refresh.disabled = false;
    document.forms[0].elements.IP_ADDRESS.disabled = true;
    document.forms[0].elements.SUBNET_MASK.disabled = true;
    document.forms[0].elements.GATEWAY_ADDRESS.disabled = true;
  }
  top.popUpWindown('alert','DHCP Mode','Changing protocol mode will reset IP configuration!');
}

function changeRefreshVal()
{
  var re_fresh = document.getElementById('refresh');
  if (re_fresh.checked)
  {
    re_fresh.value = '1';
  }
  else
  {
    re_fresh.value = '0';
  }
}
</script>
</head>

<body  class="" onload="selectOptions();initErrMsg('Switch Information');">
<form method="post" ACTION="/iss/specific/sysInfo.html">
<input type="hidden" name="Gambit" value="__GAMBIT__">
<input type="hidden" id="refreshFlag" name="refreshFlag" value="0">
<script>
    (function(){
        var refreshFlag = document.getElementById("refreshFlag");
        if( refreshFlag.value === "1" ){
            top.document.getElementsByName("lv1")[0].click();
        }
    })();
</script>
<table class="detailsAreaContainer">
  <tr>
  	<td>
  		<table class="tableStyle">
  			<tr>
  			  <script>tbhdrTable('Switch Information','switchInformation')</script>
  			</tr>
  			<tr>
  			  <td class="paddingTableBody" colspan="2">
  			    <table class="tableStyle" id="tbl1" style="width:745px;">
					<tr>
						<td nowrap="">Product Name</td>
						<td class="margin25Left" nowrap="">__PRODUCT_NAME__</td>
					</tr>
  			      	<tr>
  			        	<td class="padding18Top" nowrap="">Switch Name</td>
  			        	<td class="padding18Top" nowrap="" align="center">
  			        		<input type="text" name="switch_name" onmousedown="enableImage()" onkeyup="enableImage()" size="25" maxlength="20" value="__SWITCH_NAME__">
  			        	</td>
  			      	</tr>
  			      	
                                     <tr>
                                         <td class="padding18Top" nowrap="">Serial Number</td>
                                         <td class="margin25Left padding18Top" nowrap="">__SERIAL__</td>
                                     </tr>

					<tr>
						<td class="padding18Top" nowrap="">MAC Address</td>
						<td class="margin25Left padding18Top" nowrap="">__MAC__</td>
					</tr>
					<tr>
						<td class="padding18Top" nowrap="">Firmware Version</td>
						<td class="margin25Left padding18Top" nowrap="">__FIRMWARE__</td>
					</tr>
					<tr data-select-value="__DHCP_SELECT__">
						<td class="padding18Top" nowrap="">DHCP Mode</td>
						<td class="margin25Left padding18Top" nowrap="">
							<select name="dhcp_mode" id="dhcpmode" style="width:145px;" onchange="enableImage();dhcpModeChange();">
								<option value="2">Disable</option>
								<option value="1">Enable</option>
							</select>
							<input type="checkbox" name="refresh" id="refresh" value="0" style="margin:auto 5px;" onclick="enableImage();changeRefreshVal()" disabled>
							<span>Refresh<span>
						</td>
					</tr>
					<tr>
						<td class="padding18Top" nowrap="">IP Address</td>
						<td class="margin25Left padding18Top" nowrap=""><input size="15" maxlength="15" type="text" name="IP_ADDRESS" onmousedown="enableImage()" onkeyup="enableImage()" value="__IP__"></td>
					</tr>
					<tr>
						<td class="padding18Top" nowrap="">Subnet Mask</td>
						<td class="margin25Left padding18Top" nowrap=""><input size="15" maxlength="15" type="text" name="SUBNET_MASK" onmousedown="enableImage()" onkeyup="enableImage()" value="__NETMASK__"></td>
					</tr>
					<tr>
						<td class="padding18Top" nowrap="">Gateway Address</td>
						<td class="margin25Left padding18Top" nowrap=""><input size="15" maxlength="15" type="text" name="GATEWAY_ADDRESS" onmousedown="enableImage()" onkeyup="enableImage()" value="__GATEWAY__"></td>
					</tr>
  			    </table>
  			  </td>
  			</tr>
  		</table>
  	</td>
  </tr>
</table>
<script>
   var str = CreateButtons('button','Cancel','javaScript:void(0)','btn_Cancel','off');
   	   str += CreateButtons('button','Apply','javaScript:void(0)','btn_Apply','off');
   PaintButtons(str);
</script>
<input type="hidden" name="errMsg" id="errMsg" value="" disabled>
<input type="hidden" name="ACTION" value="">
</form>
</body>
</html>
`

	gs110emxStatsPrefix = `<!DOCTYPE HTML>
<html>
<head>
<title>Port Statistics</title>
<link rel="stylesheet" type="text/css" href="/style.css">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"> 
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"> 
<meta http-equiv="pragma" content="no-cache">
<script src="/frame.js" type="text/javascript"></script>
<script src="/function.js" type="text/javascript"></script>
<script type="text/javascript" language="JavaScript">
function CheckVlanMngt(tblid)
{
	var rwcount = rowcount(tblid);
	var prntId = docById(tblid);

	for (var ronum = 1; ronum < rwcount; ronum++)
	{
		if (prntId.rows[ronum].cells[0].innerHTML == "32"){
			prntId.rows[ronum].style.display = "none";
		}
		else{
			prntId.rows[ronum].style.display = "";
		}
						
	}
}

</script>
</head>
<body onLoad="initTableCss();CheckVlanMngt('tbl1');">
<form method="post" action="/iss/specific/interface_stats.html">
<input type="hidden" name="Gambit" value="__GAMBIT__">
<input type="hidden" name="ClearCounters" value="">
</form>

<form method="post" action="/iss/specific/interface_stats.html">
<table class="detailsAreaContainer">
  <tr>
  	<td>
  		<table class="tableStyle">
  		  <tr><script>tbhdrTable('Port Statistics','portStatistics')</script></tr>
  		  <tr>
  		    <td class="paddingTableBody" colspan="2">
  		      <table class="tableStyle" id="tbl1" style="width:745px;">
  		        <tr>
  		          <td class="def_TH">Port</td> 
				  <td class="def_TH spacer30Percent">Bytes Received</td> 
				  <td class="def_TH spacer30Percent">Bytes Sent</td> 
				  <td class="def_TH spacer30Percent">CRC Error Packets</td> 
  		        </tr>
  		        
  		        `

	gs110emxStatsSuffix = `</table>
  		    </td>
  		  </tr>
  		</table>
  	</td>
  </tr>
</table>
</form>
<script> 
 var str = CreateButtons('button','Clear Counters','submitClearCounters()','btn_Clear','on'); 
 str += CreateButtons('button','Refresh','refreshPortStatsForm()','btn_Refresh','on'); 
 PaintButtons(str); 
 </script> 
 </body> 
 </html> 
`

	gs110emxStatsRow = `				 <td class="def firstCol" sel="text">__PORT__</td>
				 
				 <td class="def" sel="text">__RX__</td>
				 
				 <td class="def" sel="text">__TX__</td>
				 
				 <td class="def" sel="text">__CRC__</td>
				 
  		        `

	gs110emxPortSettingsPrefix = `<!DOCTYPE HTML>
<html>
<head>
<title>Port Status</title>
<link rel="stylesheet" type="text/css" href="/style.css">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta HTTP-EQUIV="pragma" content="no-cache">
<script src="/frame.js" type="text/javascript"></script>
<script src="/script.js" type="text/javascript"></script>
<script src="/function.js" type="text/javascript"></script>
<script language="JavaScript">
function correctDescriptionWithSpace()
{
	var check_row = getElementsByClass("portID");
	var i = 0;

	for (i = 0; i < check_row.length; i ++){
		check_row[i].cells[2].innerHTML = check_row[i].cells[2].innerHTML.replace(/\s/g,"&nbsp;");;
	}
}
</script>
</head>
<body onLoad="selectOption();initTableCss();initErrMsg('Port Status');correctDescriptionWithSpace();">
<form method="post" action="/iss/specific/port_settings.html">
<input type="hidden" name="Gambit" value="GAMBITTOKEN">
<input type="hidden" name="PORT_NO" value="">
<input type="hidden" name="PORT_DESCRIPTION" value="">
<input type="hidden" name="PHYSICAL_MODE" value="">
<input type="hidden" name="PORT_CTRL_MODE" value="">
<input type="hidden" name="PORT_CTRL_DUPLEX" value="">
<input type="hidden" name="PORT_CTRL_SPEED" value="">
<input type="hidden" name="FLOW_CONTROL_MODE" value="">
<input type="hidden" name="ACTION" value="">
</form>
<form method="post" action="/iss/specific/port_settings.html">
<table class="detailsAreaContainer">
  <tr>
    <td>
      <table class="tableStyle">
        <tr><script>tbhdrTable('Port Status','portStatus')</script></tr>
        <tr>
          <td class="paddingTableBody" colspan="2" id="contentTableBody">
            <table class="tableStyle" id="tbl1" style="width:600px;">
              <tr>
                <td class="def_TH spacer4Percent def_center"><input type="checkbox" name="checkALL" rownumber="" value="notchecked" onclick="checkAllCheckedRows('portID');saveSelectedPorts('tbl1');" /></td>
                <td class="def_TH">Port</td>
                <td class="def_TH spacer50Percent">Port Description</td>
                <td class="def_TH spacer40Percent">Port Status</td>
                <td class="def_TH spacer22Percent">Speed</td>
                <td class="def_TH spacer50Percent">Linked Speed</td>
                <td class="def_TH spacer22Percent">Flow Control</td>
                <td class="def_TH spacer22Percent">Max MTU</td>
              </tr>
              <tr id="g_1_1" exclusive="">
                <td class="def_TH def_center"></td>
                <td class="def_TH" sel="text"></td>
                <td class="def_TH" sel="input"><input name="DESCRIPTION" maxlength="20" style="padding:0px;height:17px;" type="text" disabled>
                </td>
                <td class="def_TH" sel="plain"></td>
                <td class="def_TH" sel="select"><select name="PHYSICAL_MODE" disabled>
                       <option value ="0"></option>
                       <option value ="1">Auto</option>
                       <option value ="6">Disable</option>
                       <option value ="2">10M Half</option>
                       <option value ="3">10M Full</option>
                       <option value ="4">100M Half</option>
                       <option value ="5">100M Full</option>
                    </select>
                </td>
                <td class="def_TH" sel="plain"></td>
                <td class="def_TH" sel="select"><select name="FLOW_CONTROL_MODE" disabled>
                        <option value="0"></option>
                        <option value="1">Disable</option>
                        <option value="4">Enable</option>
                    </select>
                </td>
                <td class="def_TH" sel="plain"></td>
              </tr>
              
              `

	gs110emxPortSettingsRow = `<tr class="portID">
<td class="def firstCol def_center"><input class="checkbox" type="checkbox" name="checkbox" value="checked">
</td>
<td class="def firstCol" sel="text">__PORT__
<input type="hidden" name="PORT_NO" value="__PORT__" >
</td>
<td class="def" sel="text">__DESC__</td>
<td class="def" sel="text">__LINK__</td>
<td class="def" id="an" sel="select">__MODE__
<input type="hidden" name="PHYSICAL_MODE" value="__PHYSMODE__" >
</td>
<td class="def" sel="text">__SPEED__</td>
<td class="def" id="fc" sel="select">Enable
<input type="hidden" name="FLOW_CONTROL_MODE" value="4" >
</td>
<td class="def" sel="text">10240</td>
`

	gs110emxPortSettingsSuffix = `</table>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
<input type="hidden" name="selectedPorts" id="selectedPorts" size="2700" maxlength="2699" value="" >
<input type="hidden" name="mutiple_ports" id="mutiple_ports" size="4" maxlength="3" value="" >
<input type="hidden" name="lagStatus" value="" disabled>
<input type="hidden" name="errMsg" id="errMsg" value="" disabled>
</form>
<script>
    var str = CreateButtons("button","Refresh","resetForm()","btn_Refresh","on");
    str += CreateButtons("button","Apply","javascript:void(0)","btn_Apply","off");
    PaintButtons(str);
</script>
</body>
</html>
`

	gs110emxPvidPrefix = `<!DOCTYPE html> 
 <html> 
 <title>PVID Configuration</title> 
 <meta http-equiv="Content-Type" content="text/html; charset=utf-8"> 
 <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"> 
 <link rel="stylesheet" type="text/css" href="/style.css"> 
 <script src="/frame.js" type="text/javascript"></script> 
 <script src="/function.js" type="text/javascript"></script> 
 </head> 
 <body onload="initTableCss();initErrMsg('Port PVID');"> 
 <form method="post" action="/iss/specific/vlan_pvidsetting.html">
 <input type="hidden" name="Gambit" value="GAMBITTOKEN">
 <input type="hidden" name="PORT_NO" value="">
 <input type="hidden" name="PORT_PVID" value="">
 <input type="hidden" name="ACTION" value="">
 </form>
 <form method="post" action="/iss/specific/vlan_pvidsetting.html">
 <table class="detailsAreaContainer"> 
   <tr>
     <td>
       <table class="tableStyle">
         <tr> 
		 <script>tbhdrTable('PVID Configuration','advance8021qPvid')</script> 
		 </tr> 
		 <tr>
		   <td class="paddingTableBody" colspan="2">
		     <table class="tableStyle" id="tbl1" style='width:360px;'>
		       <tr>
		         <td class="def_TH spacer4Percent def_center"><input type="checkbox" name="checkALL" rownumber="" value="notchecked" onclick="checkAllCheckedRows('portID');saveSelectedPorts('tbl1');" /></td> 
		         <td class="def_TH secCell">Port</td>
		         <td class="def_TH thirCell">PVID</td>
		       </tr> 
		       <tr id="g_1_1" exclusive="">
		         <td class="def_TH def_center"></td> 
                 <td class="def_TH" sel="text"></td>
                 <td class="def_TH" sel="input"><input type="text" name="pvid" value="" maxlength="4" size="20" disabled onkeypress="return checkForNumber(1,4094,event,this);" onkeyup="return checkForNumber(1,4094,event,this);"> 
                 </td>  
		       </tr>
		       
		       `

	gs110emxPvidRow = `<tr class="portID">
<td class="def firstCol def_center"><input type="checkbox" name="checkbox"></td>
<td class="def" sel="text">__PORT__</td>
<td class="def" sel="input">__PVID__</td>
`

	gs110emxPvidSuffix = `</table>
		   </td>
		 </tr>
       </table>
     </td>
   </tr>
 </table>
<input type="hidden" name="selectedPorts" id="selectedPorts" size="2700" maxlength="2699" value="">
<input type="hidden" name="lagStatus" value="" disabled>
<input type="hidden" name="errMsg" id="errMsg" value="" disabled>
 </form>
 <script> 
 var str = CreateButtons('button','Cancel','javaScript:void(0)','btn_Cancel','off'); 
 str += CreateButtons('button','Apply','javaScript:void(0)','btn_Apply','off'); 
 PaintButtons(str); 
 </script> 
 </body>
 </html>`

	gs110emxCf8021qPrefix = `<!DOCTYPE HTML>
<html>
<head>
<title>Advanced 802.1Q VLAN Configuration</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<link rel="stylesheet" type="text/css" href="/style.css">
<script src="/frame.js" type="text/javascript"></script>
<script src="/function.js" type="text/javascript"></script>
<script type="text/javascript" language="JavaScript">
function saveSelectedVLANs(tblid)
{
	var rwcount = rowcount(tblid);
	var selPort = document.forms[0].elements['selectedVLANs'];
	var prntId = docById(tblid);
	var j = 0;

	for (var ronum = 2; ronum < rwcount; ronum++)
	{
		var inputs = prntId.rows[ronum].cells[0].getElementsByTagName("input");
		if (inputs[0].checked)
		{
			if (j == 0){						
				selPort.value = prntId.rows[ronum].cells[1].innerHTML + ';';
				j++;
			}
			else {
				selPort.value += prntId.rows[ronum].cells[1].innerHTML + ';';
				j++;
			}
		}						
	}
}
</script>
</head>
<body onload="selectObj();initTableCss();initRadioCtrlPage('advacedVlan'); initErrMsg('802.1Q');"> 
<form method="post" action="/iss/specific/Cf8021q.html">
<input type="hidden" name="Gambit" value="GAMBITTOKEN">
<table class="detailsAreaContainer"> 
  <tr>
    <td>
      <table class="tableStyle">
        <tr> 
		 <script>tbhdrTable('Advanced 802.1Q VLAN Status','advance8021qVlanStatus')</script> 
		</tr>
		<tr>
		  <td class="paddingTableBody" colspan="2">
		    <table class="tableStyle" style="width:745px;">
		      <tr data-select-value="Enable"> 
				 <td class="def firstCol" nowrap=""  style="width:50%">Advanced 802.1Q VLAN</td> 
				 <td class='def firstCol' nowrap=''><input class="radioStyle" type='radio' value='Disable' name='status' disabled /><span>Disable</span></td> 
				 <td class='def firstCol' nowrap=''><input class="radioStyle" type='radio' value='Enable' name='status' disabled /><span>Enable</span></td> 
			   </tr> 
		    </table>
		  </td>
		</tr>
      </table>
    </td>
  </tr>
  <tr><td height='40'></td></tr> 
  <tr id="tblDisplay" style="display:none;">
    <td>
      <table class="tableStyle">
        <tr> 
		 <script>tbhdrTable('VLAN Identifier Setting','advance8021qVlanId')</script> 
		 </tr> 
		 <tr>
		   <td class="paddingTableBody" colspan="2">
		     <table class="tableStyle" id="tbl1" style="width:745px;">
		       <tr class="trBgColor">
		         <td class='border_left border_bottom' colspan='3'>
		           <div class="right_th font11">
		             <label>VLAN ID</label>
		             <input type="text" id="idSetInput" name="ADD_VLANID" maxlength="4" value="" onkeypress="return checkForNumber(1,4094,event,this);" onkeyup="checkForNumber(1,4094,event,this);enableAddBtn()" onclick="enableAddBtn()"/>
		           </div>
		         </td>
		       </tr>
		       <tr id="g_1_1" class="tableHead"> 
		         <td class="def_TH spacer4Percent"><input type="checkbox" onclick="checkAllCheckedRows('vlanID');saveSelectedVLANs('tbl1');" name="checkALL" value="notchecked" ></td> 
		         <td class="def_TH">VLAN ID</td> 
 				 <td class="def_TH">Port Members</td> 
		       </tr>
		       
		       `

	gs110emxCf8021qRow = `<tr class="vlanID tableTr">
<td class="def firstCol"><input type="checkbox" name="checkbox"></td>
<td class="def">__VID__</td>
<td class="def">__MEMBERS__</td>
`

	gs110emxCf8021qSuffix = `</table>
		   </td>
		 </tr>
      </table>
    </td>
  </tr>
</table>
<input type="hidden" name="selectedVLANs" id="selectedVLANs" size="2700" maxlength="2699" value="">
<input type="hidden" name="errMsg" id="errMsg" value="" disabled>
<input type="hidden" name="ACTION" value="">
</form>
<script> 
 var str = CreateButtons('button','Delete','javascript:void(0)','btn_Delete','off'); 
 str += CreateButtons('button','Add','javascript:void(0)','btn_Add','off'); 
 PaintButtons(str); 
 </script> 
</body>
</html>
`

	gs110emxVlanmemPage = `<!DOCTYPE html>
<html>
<head>
<title>VLAN Membership</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<link rel="stylesheet" type="text/css" href="/style.css">
<script src="/frame.js" type="text/javascript"></script>
<script src="/function.js" type="text/javascript"></script>
</head>
<body onload="selectOption();initMemberAndMirror('Membership'); initErrMsg('802.1Q');">
<form method="post" action="/iss/specific/vlanMembership.html">
<input type="hidden" name="Gambit" value="GAMBITTOKEN">
<table class="detailsAreaContainer">
  <tr>
    <td>
      <table class="tableStyle">
        <tr>
		<script>tbhdrTable('VLAN Membership','advance8021qVlanMember')</script>
		</tr>
		<tr>
		  <td class="paddingTableBody" colspan="2">
		    <table class="tableStyle" style="width:745px;">
		      <tr class="trBgColor">
		        <td>
		          <span class="left_th">Options</span>
		          <div class="right_th">
	                <label>VLAN ID</label>
					<select name="VLAN_ID" id="vlanIdOption">__VLAN_OPTIONS__</select>
				    <input type="hidden" name="vlanIdSel" value="1">
				    <label>Group Operation</label>
					<select name="" id="groupOpera">
					  <option value="-1"></option>
					  <option value="0">Untag All</option>
					  <option value="1">Tag All</option>
					  <option value="2">Remove All</option>
					</select>
				   </div>
				 </td>
			   </tr>
			   <tr class="">
			     <td class="borderRight textCenter" id="unit1" style="padding-top:10px">
			       <span class="ports">Ports</span>
			       <div class='portMember margin'><span class='portword'>1</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>2</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>3</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>4</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>5</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>6</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>7</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>8</span><div class='panels'><div class='portImage untImg'></div></div></div>
<div class='portMember margin'><span class='portword'>9</span><div class='panels'><div class='portImage tagImg'></div></div></div>
<div class='portMember margin'><span class='portword'>10</span><div class='panels'><div class='portImage tagImg'></div></div></div>

			     </td>
			   </tr>
                        <tr><td style="height:20px;"></td></tr>
                        <tr>
                            <td class="font11 borderRight textCenter" style="padding-top:10px">
                                <span class="ports font11">LAG&nbsp;</span>
                                <div class='portMember margin'><span class='portword'>1</span><div class='panels'><div class='lagImage'></div></div></div>
<div class='portMember margin'><span class='portword'>2</span><div class='panels'><div class='lagImage'></div></div></div>
<div class='portMember margin'><span class='portword'>3</span><div class='panels'><div class='lagImage'></div></div></div>
<div class='portMember margin'><span class='portword'>4</span><div class='panels'><div class='lagImage'></div></div></div>
<div class='portMember margin'><span class='portword'>5</span><div class='panels'><div class='lagImage'></div></div></div>

                                </td>
                            </tr>
		    </table>
		  </td>
		</tr>
      </table>
    </td>
  </tr>
</table>
<input name="hiddenMem" id="hiddenMem" value="__HIDDENMEM__" type="hidden">
<input type="hidden" name="lagStatus" value="" disabled>
<input type="hidden" name="errMsg" id="errMsg" value="" disabled>
<input type="hidden" name="ACTION" value="">
</form>
<script>
var str = CreateButtons('button','Cancel','javaScript:void(0)','btn_Cancel','off');
str += CreateButtons('button','Apply','javaScript:void(0)','btn_Apply','off');
PaintButtons(str);
</script>
</body>
</html>
`
)

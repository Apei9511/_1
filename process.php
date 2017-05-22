<?php include("connect.php"); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Watchlogs</title>

    <link rel="stylesheet" type="text/css" href="bootstrap/css/bootstrap.min.css" />
    <link rel="stylesheet" type="text/css" href="font-awesome/css/font-awesome.min.css" />
    <link rel="stylesheet" type="text/css" href="css/local.css" />

    <script type="text/javascript" src="js/jquery-1.10.2.min.js"></script>
    <script type="text/javascript" src="bootstrap/js/bootstrap.min.js"></script>
    <link rel="stylesheet" type="text/css" href="css/light-bootstrap/all.min.css" />
    <link id="gridcss" rel="stylesheet" type="text/css" href="css/dark-bootstrap/all.min.css" />

    <script type="text/javascript" src="js/shieldui-all.min.js"></script>
</head>
<body>
    <div id="wrapper">
        <nav class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="index.php">W7-watchlogs : <?php echo $_SERVER['SERVER_NAME']; ?> </a>
            </div>
            <div class="collapse navbar-collapse navbar-ex1-collapse">
                <ul id="active" class="nav navbar-nav side-nav">
					<li><a href="index.php"><i class="fa fa-bullseye"></i> Principal</a></li>				
					<li><a href="menu.php"><i class="fa fa-tasks"></i> Menu de recherche</a></li>
					<li><a href=""><i class="fa fa-table"></i> Statistiques</a></li>
					<li><a href="phppgadmin/"><i class="fa fa-list-ol"></i> PhpPgAdmin</a></li>
					<li><a href="https://172.29.21.5:4130/auth/login"><i class="fa fa-list-ul"></i> Watchguard</a></li>
                </ul>
            </div>
        </nav>


<?php

if(isset($_POST)==true && empty($_POST)==false) {

	$data00		=	$_POST['data00'];
	$data01		=	$_POST['data01'];
	if (empty($data01)==true) { $data01="00:00"; }
	$data10		=	$_POST['data10'];
	$data11		=	$_POST['data11'];
	if (empty($data11)==true) { $data11="00:00"; }	
	$chkbox 	= 	$_POST['chk']; 
	$table 		= 	$_POST['PassTables'];
	$ip 		= 	$_POST['BX_ip'];
	$path 		= 	$_POST['BX_path'];
	$etat 		= 	$_POST['BX_etat'];
	$port 		= 	$_POST['BX_port'];
	$rule 		= 	$_POST['BX_rule'];
	$CLS = NULL;
}
/*
echo $data00."&nbsp;".$data01."</br>".$data10."&nbsp;".$data11."</br>";
foreach($table as $a => $b)	{ echo $a." : ".$table[$a]."</br>"; 	} 
foreach($ip as $a => $b)	{ echo $a." : ".$ip[$a]."</br>"; 		} 
foreach($path as $a => $b)	{ echo $a." : ".$path[$a]."</br>"; 		} 
foreach($etat as $a => $b)	{ echo $a." : ".$etat[$a]."</br>"; 		} 
foreach($port as $a => $b)	{ echo $a." : ".$port[$a]."</br>"; 		}  
foreach($rule as $a => $b)	{ echo $a." : ".$rule[$a]."</br>";		}  
*/
$SELECT = "SELECT msg, policy, protocol, src_ip, src_port,src_intf,  dst_ip, dst_port, dst_intf, update_time";

foreach ($ip as $a => $b) {

	$C0000 = (($path[$a] === "Path (Optionnel)") 	&& ($etat[$a] === "Etat (Optionnel)"));
	$C0001 = (($path[$a] === "Path (Optionnel)") 	&& ($etat[$a] === "Allowed"));
	$C0010 = (($path[$a] === "Path (Optionnel)") 	&& ($etat[$a] === "Denied"));
	$C0011 = (($path[$a] === "Destination") 		&& ($etat[$a] === "Etat (Optionnel)"));
	$C0100 = (($path[$a] === "Destination") 		&& ($etat[$a] === "Allowed"));
	$C0101 = (($path[$a] === "Destination") 		&& ($etat[$a] === "Denied"));
	$C0110 = (($path[$a] === "Source") 				&& ($etat[$a] === "Etat (Optionnel)"));
	$C0111 = (($path[$a] === "Source") 				&& ($etat[$a] === "Allowed"));
	$C1000 = (($path[$a] === "Source") 				&& ($etat[$a] === "Denied"));
	$D1001 = ((isset($port[$a])==true 	&& empty($port[$a])==false) && (isset($rule[$a])==true && empty($rule[$a])==false));
	$D1010 = ((isset($port[$a])==true 	&& empty($port[$a])==false) && (empty($rule[$a])==true));
	$D1011 = ((empty($port[$a])==true) 	&& (isset($rule[$a])==true 	&& empty($rule[$a])==false));
	$D1100 = (empty($port[$a])==true 	&& empty($rule[$a])==true);
	
	if 			($C0000 && $D1001) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 						AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0000 && $D1010) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 						AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0000 && $D1011) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 															AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0000 && $D1100) {	$CLS[]= "(	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]')																								 ";	
	} elseif 	($C0001 && $D1001) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 	AND msg ='Allowed' 	AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0001 && $D1010) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 	AND msg ='Allowed' 	AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0001 && $D1011) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 	AND msg ='Allowed' 										AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0001 && $D1100) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]')		AND msg ='Allowed'																		)";	
	} elseif 	($C0010 && $D1001) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 	AND msg ='Denied' 	AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0010 && $D1010) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 	AND msg ='Denied' 	AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0010 && $D1011) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]') 	AND msg ='Denied' 										AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0010 && $D1100) {	$CLS[]= "((	src_ip ='$ip[$a]' OR dst_ip ='$ip[$a]')		AND msg ='Denied'																		)";
	} elseif 	($C0011 && $D1001) {	$CLS[]= "(	dst_ip ='$ip[$a]' 												AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0011 && $D1010) {	$CLS[]= "(	dst_ip ='$ip[$a]' 												AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0011 && $D1011) {	$CLS[]= "(	dst_ip ='$ip[$a]' 																					AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0011 && $D1100) {	$CLS[]= "(	dst_ip ='$ip[$a]' 																													)";	
	} elseif 	($C0100 && $D1001) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Allowed' 	AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0100 && $D1010) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Allowed' 	AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0100 && $D1011) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Allowed' 										AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0100 && $D1100) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Allowed'																		)";	
	} elseif 	($C0101 && $D1001) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Denied' 	AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0101 && $D1010) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Denied' 	AND protocol 	like '%$port[$a]%'									)";				
	} elseif 	($C0101 && $D1011) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Denied' 										AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0101 && $D1100) {	$CLS[]= "(	dst_ip ='$ip[$a]' 							AND msg ='Denied'																		)";	
	} elseif 	($C0110 && $D1001) {	$CLS[]= "(	src_ip ='$ip[$a]' 												AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0110 && $D1010) {	$CLS[]= "(	src_ip ='$ip[$a]' 												AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0110 && $D1011) {	$CLS[]= "(	src_ip ='$ip[$a]' 																					AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0110 && $D1100) {	$CLS[]= "(	src_ip ='$ip[$a]'																													)";	
	} elseif 	($C0111 && $D1001) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Allowed' 	AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0111 && $D1010) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Allowed' 	AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C0111 && $D1011) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Allowed' 										AND policy like '%$rule[$a]%'	)";
	} elseif 	($C0111 && $D1100) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Allowed'																		)";	
	} elseif 	($C1000 && $D1001) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Denied' 	AND protocol 	like '%$port[$a]%' 	AND policy like '%$rule[$a]%'	)";
	} elseif 	($C1000 && $D1010) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Denied' 	AND protocol 	like '%$port[$a]%'									)";
	} elseif 	($C1000 && $D1011) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Denied' 										AND policy like '%$rule[$a]%'	)";
	} elseif 	($C1000 && $D1100) {	$CLS[]= "(	src_ip ='$ip[$a]' 							AND msg ='Denied'																		)";
	}
}

foreach($table as $a => $b)	{ 
	$SQL = $SELECT.' FROM '.$table[$a].' WHERE '.implode(' OR ',$CLS).' AND (update_time BETWEEN \' '.$data00.' '.$data01.':00 \' AND \' '.$data10.' '.$data11.':00 \')'; 
	$QUERY= pg_query($SQL);
	//$SQL_html = implode(' ', $SQL);
}

//$QUERY= pg_query($SQL_html);
?>
	<table class='table table-hover'>
		<thead>
			<tr>
				<th>Message</th>
				<th>Policy</th>
				<th>Protocole</th>
				<th>IP Source</th>
				<th>Port Source</th>
				<th>Int Source</th>
				<th>IP Destination</th>
				<th>Port Destination</th>
				<th>Int Destination</th>
				<th>Date</th>
			</tr>
		</thead>
		<tbody>
<?php		
while($tab = pg_fetch_row($QUERY)) {
	echo "<tr>";

	for($i=0;$i<pg_num_fields($QUERY);$i++) {
		echo "<td>";
		echo "&nbsp;".$tab[$i]; 	
		echo "</td>";
	}
	echo "</tr>";
/*
foreach($SQL as $a => $b) { $QUERY[]= pg_query($SQL[$a]); }
foreach($QUERY as $a => $b) { echo '</br>'.implode(' ',$QUERY); }
*/
}
?>

		</tbody>
	</table>
	</div>
</body>
</html>
	
	

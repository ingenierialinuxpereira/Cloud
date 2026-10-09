#!/bin/bash

############################################################
# AWS Enterprise Inventory Dashboard
#
# Author: Francisco Gutierrez
# Role: Cloud Linux Engineer
# Company: Amrize
# Year: 2026
#
# Generates:
#   - aws_inventory.csv
#   - aws_inventory.json
#   - aws_inventory.html
#
# Requirements:
#   awscli v2
#   jq
############################################################

set -euo pipefail

#############################################
# Runtime Variables
#############################################

CSV="aws_inventory.csv"
JSON="aws_inventory.json"
HTML="aws_inventory.html"

START_TIME=$(date +%s)

#############################################
# Terminal Colors
#############################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

#############################################
# Banner
#############################################

clear

echo -e "${BLUE}"

cat << "EOF"

    █████╗ ██╗    ██╗███████╗
   ██╔══██╗██║    ██║██╔════╝
   ███████║██║ █╗ ██║███████╗
   ██╔══██║██║███╗██║╚════██║
   ██║  ██║╚███╔███╔╝███████║
   ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝

   AWS Enterprise Inventory Dashboard

EOF

echo -e "${NC}"

echo -e "${CYAN}Author : Francisco Gutierrez${NC}"
echo -e "${CYAN}Role   : Cloud Linux Engineer${NC}"
echo -e "${CYAN}Company: Amrize${NC}"
echo -e "${CYAN}Year   : 2026${NC}"

echo
echo -e "${GREEN}[INFO] Starting inventory collection...${NC}"
echo

#############################################
# CSV Initialization
#############################################

echo "Service,Region,ResourceType,ResourceName,ARN" > "$CSV"

collect_csv() {
    echo "$1,$2,$3,$4,$5" >> "$CSV"
}

#############################################
# Discover Tagged Resources
#############################################

echo -e "${YELLOW}[INFO] Discovering tagged AWS resources...${NC}"

aws resourcegroupstaggingapi get-resources \
    --output json > tagged.json \
    || echo '{"ResourceTagMappingList":[]}' > tagged.json

DISCOVERED=0

jq -r '.ResourceTagMappingList[].ResourceARN' tagged.json |
while read -r arn; do

    svc=$(echo "$arn" | cut -d: -f3)
    reg=$(echo "$arn" | cut -d: -f4)
    name=$(basename "$arn")

    collect_csv "$svc" "$reg" "Discovered" "$name" "$arn"

done

DISCOVERED=$(jq '.ResourceTagMappingList | length' tagged.json)

echo -e "${GREEN}[SUCCESS] Tagged resources discovered: ${DISCOVERED}${NC}"

#############################################
# Region Discovery
#############################################

REGIONS=$(tail -n +2 "$CSV" \
    | cut -d, -f2 \
    | sort -u \
    | grep -v '^$' || true)

if [ -z "$REGIONS" ]; then
    echo -e "${RED}[WARNING] No regions discovered via tagging API${NC}"
fi

#############################################
# Inventory Counters
#############################################

EC2_COUNT=0
RDS_COUNT=0
LAMBDA_COUNT=0
DYNAMODB_COUNT=0

#############################################
# Region Loop
#############################################

for REGION in $REGIONS
do

    echo
    echo -e "${PURPLE}======================================${NC}"
    echo -e "${PURPLE}Scanning Region: ${REGION}${NC}"
    echo -e "${PURPLE}======================================${NC}"

    #########################################
    # EC2
    #########################################

    echo -e "${CYAN}[EC2] Discovering instances...${NC}"

    aws ec2 describe-instances \
        --region "$REGION" \
        --query 'Reservations[].Instances[].InstanceId' \
        --output text | wc -w |
        tr '\t' '\n' |
        sed '/^$/d' |
        while read -r x
        do
            collect_csv ec2 "$REGION" Instance "$x" ""
        done || true

    COUNT=$(aws ec2 describe-instances \
       --region "$REGION" \
       --query 'Reservations[].Instances[].InstanceId' \
       --output text 2>/dev/null | wc -w || echo 0)

    [[ "$COUNT" == "None" ]] && COUNT=0
    EC2_COUNT=$((EC2_COUNT + COUNT))

    #########################################
    # RDS
    #########################################

    echo -e "${CYAN}[RDS] Discovering databases...${NC}"

    aws rds describe-db-instances \
        --region "$REGION" \
        --query 'DBInstances[].DBInstanceIdentifier' \
        --output text 2>/dev/null |
        tr '\t' '\n' |
        sed '/^$/d' |
        while read -r x
        do
            collect_csv rds "$REGION" Database "$x" ""
        done || true

    COUNT=$(aws rds describe-db-instances \
        --region "$REGION" \
        --query 'length(DBInstances)' \
        --output text 2>/dev/null || echo 0)

    [[ "$COUNT" == "None" ]] && COUNT=0
    RDS_COUNT=$((RDS_COUNT + COUNT))

    #########################################
    # Lambda
    #########################################

    echo -e "${CYAN}[Lambda] Discovering functions...${NC}"

    aws lambda list-functions \
        --region "$REGION" \
        --query 'Functions[].FunctionName' \
        --output text 2>/dev/null |
        tr '\t' '\n' |
        sed '/^$/d' |
        while read -r x
        do
            collect_csv lambda "$REGION" Function "$x" ""
        done || true

    COUNT=$(aws lambda list-functions \
        --region "$REGION" \
        --query 'Functions[].FunctionName' \
        --output text 2>/dev/null | wc -w)

    COUNT=${COUNT:-0}

    LAMBDA_COUNT=$((LAMBDA_COUNT + COUNT))

    #########################################
    # DynamoDB
    #########################################

    echo -e "${CYAN}[DynamoDB] Discovering tables...${NC}"

    aws dynamodb list-tables \
        --region "$REGION" \
        --query 'TableNames[]' \
        --output text 2>/dev/null |
        tr '\t' '\n' |
        sed '/^$/d' |
        while read -r x
        do
            collect_csv dynamodb "$REGION" Table "$x" ""
        done || true

    COUNT=$(aws dynamodb list-tables \
        --region "$REGION" \
        --query 'length(TableNames)' \
        --output text 2>/dev/null || echo 0)

    [[ "$COUNT" == "None" ]] && COUNT=0
    DYNAMODB_COUNT=$((DYNAMODB_COUNT + COUNT))

done

#############################################
# Build JSON
#############################################

echo
echo -e "${YELLOW}[INFO] Building JSON inventory...${NC}"

jq -Rn '
[inputs|split(",")] |
.[1:] |
map({
 service:.[0],
 region:.[1],
 type:.[2],
 name:.[3],
 arn:.[4]
})
' < "$CSV" > "$JSON"

#############################################
# Global Statistics
#############################################

SERVICES=$(tail -n +2 "$CSV" | cut -d, -f1 | sort -u | wc -l)
REGIONCOUNT=$(tail -n +2 "$CSV" | cut -d, -f2 | sort -u | grep -v '^$' | wc -l)
RESOURCES=$(( $(wc -l < "$CSV") - 1 ))

TOP_SERVICE=$(tail -n +2 "$CSV" \
    | cut -d, -f1 \
    | sort \
    | uniq -c \
    | sort -nr \
    | head -1 \
    | awk '{print $2}')

TOP_REGION=$(tail -n +2 "$CSV" \
    | cut -d, -f2 \
    | grep -v '^$' \
    | sort \
    | uniq -c \
    | sort -nr \
    | head -1 \
    | awk '{print $2}')

echo -e "${GREEN}[SUCCESS] Statistics calculated.${NC}"

#############################################
# Chart Data
#############################################

SERVICE_LABELS=$(tail -n +2 "$CSV" \
| cut -d, -f1 \
| sort \
| uniq \
| jq -R . \
| jq -s .)

SERVICE_COUNTS=$(tail -n +2 "$CSV" \
| cut -d, -f1 \
| sort \
| uniq -c \
| awk '{print $1}' \
| jq -R . \
| jq -s 'map(tonumber)')

REGION_LABELS=$(tail -n +2 "$CSV" \
| cut -d, -f2 \
| grep -v '^$' \
| sort \
| uniq \
| jq -R . \
| jq -s .)

REGION_COUNTS=$(tail -n +2 "$CSV" \
| cut -d, -f2 \
| grep -v '^$' \
| sort \
| uniq -c \
| awk '{print $1}' \
| jq -R . \
| jq -s 'map(tonumber)')

#############################################
# HTML Report
#############################################

echo
echo -e "${YELLOW}[INFO] Building HTML dashboard...${NC}"

cat > "$HTML" <<EOF
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>AWS Enterprise Inventory Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

*{
    box-sizing:border-box;
}

html{
    scroll-behavior:smooth;
}

body{
    margin:0;
    font-family:'Segoe UI',sans-serif;
    background:#0f172a;
    color:#e2e8f0;
}

.sidebar{
    position:fixed;
    top:0;
    left:0;
    width:260px;
    height:100%;
    background:#111827;
    padding:25px;
    overflow:auto;
    border-right:1px solid #334155;
}

.sidebar h2{
    color:#ff9900;
    margin-top:0;
}

.sidebar a{
    display:block;
    color:#cbd5e1;
    text-decoration:none;
    padding:10px;
    margin-bottom:8px;
    border-radius:8px;
    transition:.3s;
}

.sidebar a:hover{
    background:#1e293b;
    color:#ff9900;
}

.content{
    margin-left:280px;
    padding:25px;
}

.hero{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:20px;
    padding:25px;
    border-radius:16px;
    background:linear-gradient(
        135deg,
        #111827,
        #1e293b
    );
    box-shadow:0 8px 25px rgba(0,0,0,.35);
}

.hero h1{
    margin:0;
    color:#ffffff;
}

.hero p{
    color:#94a3b8;
}

.author-box{
    min-width:260px;
    padding:20px;
    border-radius:12px;
    background:#0b1220;
    border:1px solid #334155;
}

.author-box h3{
    margin-top:0;
    color:#ff9900;
}

.author-box p{
    margin:6px 0;
}

.kpi-grid{
    display:flex;
    flex-wrap:wrap;
    margin-top:25px;
    gap:15px;
}

.card{
    flex:1;
    min-width:220px;
    padding:20px;
    border-radius:14px;
    transition:.3s;
    box-shadow:0 4px 15px rgba(0,0,0,.30);
}

.card:hover{
    transform:translateY(-5px);
}

.orange{
    background:#1e293b;
    border-left:6px solid #ff9900;
}

.green{
    background:#1e293b;
    border-left:6px solid #10b981;
}

.blue{
    background:#1e293b;
    border-left:6px solid #3b82f6;
}

.red{
    background:#1e293b;
    border-left:6px solid #ef4444;
}

.card h2{
    margin-top:0;
    font-size:16px;
    color:#94a3b8;
}

.card h1{
    margin-bottom:0;
}

.section-title{
    margin-top:40px;
    color:#ffffff;
}

.chart-container{
    margin-top:25px;
    padding:25px;
    border-radius:16px;
    background:#1e293b;
}

.chart-title{
    margin-top:0;
    color:#ff9900;
}

.search-box{
    margin-top:25px;
}

.search-box input{
    width:100%;
    max-width:700px;
    padding:12px;
    background:#111827;
    color:white;
    border:1px solid #334155;
    border-radius:8px;
}

.stats-panel{
    margin-top:25px;
    background:#1e293b;
    padding:20px;
    border-radius:14px;
}

.stats-panel table{
    width:100%;
}

.stats-panel td{
    padding:10px;
}

details{
    background:#1e293b;
    margin-top:15px;
    border-radius:12px;
    overflow:hidden;
    transition:.3s;
}

details:hover{
    border-left:4px solid #ff9900;
}

summary{
    cursor:pointer;
    padding:15px;
    font-weight:bold;
    color:#ff9900;
}

table{
    width:100%;
    border-collapse:collapse;
}

th{
    background:#111827;
    color:#ffffff;
}

th,td{
    border:1px solid #334155;
    padding:10px;
    text-align:left;
}

tbody tr:nth-child(even){
    background:#172033;
}

tbody tr:hover{
    background:#253147;
}

.footer{
    margin-top:40px;
    text-align:center;
    padding:25px;
    background:#111827;
    border-radius:12px;
    color:#94a3b8;
}

.badge{
    display:inline-block;
    background:#ff9900;
    color:black;
    padding:4px 10px;
    border-radius:999px;
    font-size:12px;
    font-weight:bold;
}

@media (max-width:900px){

.sidebar{
    position:relative;
    width:100%;
    height:auto;
}

.content{
    margin-left:0;
}

.hero{
    flex-direction:column;
}

}

</style>

<script>

function filterRows(){

    let filter =
        document
        .getElementById("search")
        .value
        .toUpperCase();

    document
    .querySelectorAll("tbody tr")
    .forEach(function(row){

        row.style.display =
            row.innerText.toUpperCase()
            .includes(filter)
            ? ""
            : "none";

    });

}

</script>

</head>

<body>

<div class="sidebar">

<h2>☁ AWS Dashboard</h2>

<a href="#summary">Executive Summary</a>
<a href="#analytics">Analytics</a>
<a href="#inventory">Inventory</a>

<br>

<div class="badge">
CloudOps Edition
</div>

</div>

<div class="content">

<div class="hero">

<div>

<h1>AWS Enterprise Inventory Dashboard</h1>

<p>
Enterprise Cloud Resource Discovery,
Governance and Inventory Reporting Platform
</p>

</div>

<div class="author-box">

<h3>Author Information</h3>

<p><strong>Francisco Gutierrez</strong></p>
<p>Cloud Linux Engineer</p>
<p>Amrize</p>
<p>2026</p>

</div>

</div>

<div id="summary" class="kpi-grid">

<div class="card orange">
<h2>Services</h2>
<h1>$SERVICES</h1>
</div>

<div class="card green">
<h2>Resources</h2>
<h1>$RESOURCES</h1>
</div>

<div class="card blue">
<h2>Regions</h2>
<h1>$REGIONCOUNT</h1>
</div>

<div class="card red">
<h2>Generated</h2>
<h3>$(date)</h3>
</div>

</div>

<div class="stats-panel">

<h2>Inventory Statistics</h2>

<table>

<tr>
<td><strong>Top Service</strong></td>
<td>$TOP_SERVICE</td>
</tr>

<tr>
<td><strong>Top Region</strong></td>
<td>$TOP_REGION</td>
</tr>

<tr>
<td><strong>EC2 Instances</strong></td>
<td>$EC2_COUNT</td>
</tr>

<tr>
<td><strong>RDS Databases</strong></td>
<td>$RDS_COUNT</td>
</tr>

<tr>
<td><strong>Lambda Functions</strong></td>
<td>$LAMBDA_COUNT</td>
</tr>

<tr>
<td><strong>DynamoDB Tables</strong></td>
<td>$DYNAMODB_COUNT</td>
</tr>

</table>

</div>

<div id="analytics" class="chart-container">

<h2 class="chart-title">
Inventory Analytics
</h2>

<canvas id="serviceChart"></canvas>

<br><br>

<canvas id="regionChart"></canvas>

</div>

<div class="search-box">

<h2>Search Inventory</h2>

<input
id="search"
onkeyup="filterRows()"
placeholder="Search services, resources, regions, names, ARNs">

</div>

<div id="inventory">

<h2 class="section-title">
Detailed Inventory
</h2>

EOF


#############################################
# Service Sections
#############################################

for svc in $(tail -n +2 "$CSV" | cut -d, -f1 | sort -u)
do

COUNT=$(grep "^$svc," "$CSV" | wc -l)

cat >> "$HTML" <<EOF

<details>

<summary>
$svc ($COUNT resources)
</summary>

<table>

<thead>
<tr>
<th>Region</th>
<th>Type</th>
<th>Name</th>
<th>ARN</th>
</tr>
</thead>

<tbody>

EOF

grep "^$svc," "$CSV" |
while IFS=',' read -r s r t n a
do

cat >> "$HTML" <<EOF
<tr>
<td>$r</td>
<td>$t</td>
<td>$n</td>
<td>$a</td>
</tr>
EOF

done

cat >> "$HTML" <<EOF

</tbody>
</table>

</details>

EOF

done

#############################################
# Charts + Footer
#############################################

cat >> "$HTML" <<EOF

</div>

<div class="footer">

<h3>AWS Enterprise Inventory Dashboard</h3>

<p>
Generated automatically from AWS API discovery
</p>

<p>
Author:
<strong>
Francisco Gutierrez
</strong>
|
Cloud Linux Engineer
|
Amrize 2026
</p>

<p>
Generated:
$(date)
</p>

<p>
Services:
$SERVICES
|
Resources:
$RESOURCES
|
Regions:
$REGIONCOUNT
</p>

</div>

</div>

<script>

/////////////////////////////////////////////////
// Service Distribution Chart
/////////////////////////////////////////////////

new Chart(
document.getElementById('serviceChart'),
{
    type:'bar',
    data:{
        labels:$SERVICE_LABELS,
        datasets:[
        {
            label:'Resources per Service',
            data:$SERVICE_COUNTS
        }]
    },
    options:{
        responsive:true,
        plugins:{
            legend:{
                labels:{
                    color:'#e2e8f0'
                }
            }
        },
        scales:{
            x:{
                ticks:{
                    color:'#e2e8f0'
                }
            },
            y:{
                ticks:{
                    color:'#e2e8f0'
                }
            }
        }
    }
}
);

/////////////////////////////////////////////////
// Region Distribution Chart
/////////////////////////////////////////////////

new Chart(
document.getElementById('regionChart'),
{
    type:'doughnut',
    data:{
        labels:$REGION_LABELS,
        datasets:[
        {
            data:$REGION_COUNTS
        }]
    },
    options:{
        responsive:true,
        plugins:{
            legend:{
                labels:{
                    color:'#e2e8f0'
                }
            }
        }
    }
}
);

</script>

</body>
</html>

EOF

#############################################
# Runtime Summary
#############################################

END_TIME=$(date +%s)
RUNTIME=$((END_TIME - START_TIME))

echo
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN} AWS INVENTORY COLLECTION COMPLETED SUCCESSFULLY${NC}"
echo -e "${GREEN}================================================${NC}"

echo
echo -e "${CYAN}Generated Files${NC}"
echo "--------------------------------------"
echo "CSV  : $CSV"
echo "JSON : $JSON"
echo "HTML : $HTML"

echo
echo -e "${CYAN}Inventory Statistics${NC}"
echo "--------------------------------------"
echo "Services  : $SERVICES"
echo "Resources : $RESOURCES"
echo "Regions   : $REGIONCOUNT"

echo
echo -e "${CYAN}Resource Breakdown${NC}"
echo "--------------------------------------"
echo "EC2       : $EC2_COUNT"
echo "RDS       : $RDS_COUNT"
echo "Lambda    : $LAMBDA_COUNT"
echo "DynamoDB  : $DYNAMODB_COUNT"

echo
echo "Top Service : $TOP_SERVICE"
echo "Top Region  : $TOP_REGION"

echo
echo -e "${GREEN}Execution Time: ${RUNTIME} seconds${NC}"

echo
echo -e "${GREEN}Dashboard ready:${NC} $HTML"
echo

#############################################
# Cleanup (Optional)
#############################################

# Uncomment if desired:
#
# rm -f tagged.json

exit 0
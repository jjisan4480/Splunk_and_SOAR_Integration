# Cybersecurity Project: Active Directory 2.0 (Splunk & SOAR Integration)

This document details the telemetry and automation phases of the Active Directory 2.0 project. It covers the installation of Splunk on an Ubuntu server, configuring Windows endpoints to forward security event logs, and building an automated incident response playbook using Shuffle (SOAR), Slack, and Active Directory.

\---

\#\# Part 4: Splunk Installation and Telemetry Configuration

**\*\*Objective:\*\*** Install Splunk Enterprise, configure Windows endpoints to send telemetry via the Universal Forwarder, and create an alert to detect unauthorized RDP authentications.

\#\#\# 1\. Install and Configure Splunk (Ubuntu Server)  
1\. SSH into your Ubuntu server.  
2\. Update and upgrade system packages:  
   \`apt-get update && apt-get upgrade \-y\`  
3\. Download the Splunk Enterprise \`.deb\` package using the \`wget\` link provided on the Splunk Free Trials page.  
4\. Install Splunk using the Debian package manager:  
   \`dpkg \-i splunk-\<version\>-linux-amd64.deb\`  
5\. Navigate to the Splunk binary directory:  
   \`cd /opt/splunk/bin\`  
6\. Start the Splunk service:  
   \`./splunk start\`  
7\. Press the **\*\*Spacebar\*\*** to scroll through the license agreement, type \`y\` to accept, and create your Splunk Administrator credentials (e.g., username \`mydfir\`).  
8\. Allow inbound traffic on port 8000 (Splunk Web). Add a rule to your cloud provider's firewall (e.g., Vultr) for TCP Port 8000 matching your host IP, and configure the Ubuntu firewall:  
   \`ufw allow 8000\`  
9\. Access the Splunk web interface via your browser: \`http://\<Splunk-Public-IP\>:8000\` and log in.  
\> *\*\[Insert Screenshot: The Splunk Web login screen showing the public IP and port 8000 in the address bar.\]\**

\#\#\# 2\. Configure Splunk Settings  
1\. Click your username in the top right corner, select **\*\*Preferences\*\***, set the Time zone to **\*\*GMT\*\***, and click **\*\*Apply\*\***.  
2\. On the left navigation pane, go to **\*\*Apps\*\*** \> **\*\*Find More Apps\*\***.  
3\. Search for \`Windows\` and install the **\*\*Splunk Add-on for Microsoft Windows\*\***. Enter your Splunk credentials to confirm the installation.  
4\. Navigate to **\*\*Settings\*\*** \> **\*\*Indexes\*\***, click **\*\*New Index\*\***, name it \`mydfir-ad\`, and click **\*\*Save\*\***.  
5\. Navigate to **\*\*Settings\*\*** \> **\*\*Forwarding and receiving\*\*** \> **\*\*Configure receiving\*\*** \> **\*\*New Receiving Port\*\***. Enter \`9997\` and click **\*\*Save\*\***.  
6\. Back in your Ubuntu SSH session, open the firewall for port 9997:  
   \`ufw allow 9997\`  
\> *\*\[Insert Screenshot: Splunk Settings showing the newly created 'mydfir-ad' index.\]\**

\#\#\# 3\. Install the Splunk Universal Forwarder (Windows Endpoints)  
*\*Perform these steps on both the Windows Test Machine and the Domain Controller.\**  
1\. Download the **\*\*Splunk Universal Forwarder\*\*** (Windows 64-bit \`.msi\`) from the Splunk website.  
2\. Run the installer, accept the license agreement, and click **\*\*Next\*\***.  
3\. Create an administrator username (e.g., \`mydfir\`) and password.  
4\. Skip the Deployment Server step by clicking **\*\*Next\*\***.  
5\. In the Receiving Indexer step, enter the **\*\*private IP address\*\*** of your Ubuntu Splunk Server and set the port to \`9997\`. Click **\*\*Next\*\*** and **\*\*Install\*\***.  
\> *\*\[Insert Screenshot: The Universal Forwarder setup wizard highlighting the Receiving Indexer IP and Port 9997 configuration.\]\**

\#\#\# 4\. Configure Telemetry Forwarding (Windows Endpoints)  
*\*Perform these steps on both the Windows Test Machine and the Domain Controller.\**  
1\. Open File Explorer and navigate to: \`C:\\Program Files\\SplunkUniversalForwarder\\etc\\system\\default\`.  
2\. Copy the \`inputs.conf\` file.  
3\. Navigate to \`C:\\Program Files\\SplunkUniversalForwarder\\etc\\system\\local\` and paste the file (grant Administrator permissions when prompted).  
4\. Open **\*\*Notepad\*\*** as Administrator. Click **\*\*File\*\*** \> **\*\*Open\*\***, change the file type filter to **\*\*All Files\*\***, and open the \`inputs.conf\` file from the \`local\` directory.  
5\. Scroll to the bottom of the file and append the following configuration to forward Security logs to your custom index:  
   \`\`\`text  
   \[WinEventLog://Security\]  
   index \= mydfir-ad  
   disabled \= false

6. Save and close the file.  
7. Open Windows **Services** as Administrator. Locate the **SplunkForwarder** service, double-click it, go to the **Log On** tab, and switch the account to **Local System account**. Click **Apply**.  
8. Right-click the **SplunkForwarder** service and select **Restart**.  
9. In the Splunk Web interface, verify logs are arriving by running the search: index="mydfir-ad".

*\[Insert Screenshot: Splunk Search app showing event logs successfully populating from the Windows endpoints.\]*

### **5\. Create an Unauthorized Login Alert**

1. In Splunk, construct a search query to identify successful RDP authentications (EventCode 4624, Logon Types 7 or 10\) originating from outside the authorized IP subnet:  
   Plaintext  
   index="mydfir-ad" EventCode=4624 (Logon\_Type=7 OR Logon\_Type=10) Source\_Network\_Address\!="-" Source\_Network\_Address\!="\<Your\_Authorized\_IP\_Subnet\>\*"  
   | stats count by \_time, ComputerName, Source\_Network\_Address, user, Logon\_Type

2. Click **Save As** \> **Alert**.  
3. Name the alert (e.g., MyDFIR-Unauthorized-Successful-Login-RDP).  
4. Set the Alert type to **Scheduled**, utilizing a Cron Schedule (e.g., \* \* \* \* \* to run every minute for lab testing).  
5. Set the Time Range to the **Last 60 minutes**.  
6. Under Trigger Actions, click **Add Actions**, select **Add to Triggered Alerts**, and assign a **Medium** severity. Click **Save**.

*\[Insert Screenshot: The configured Alert showing the schedule, trigger conditions, and the specific search query.\]*

## ---

**Part 5: Integrating SOAR (Shuffle, Slack, and Active Directory)**

**Objective:** Build an automated workflow in Shuffle that receives Splunk alerts, notifies the SOC team via Slack, requests human-in-the-loop approval via email, and automatically disables the compromised user account in Active Directory.

### **1\. Configure the Splunk Webhook in Shuffle**

1. Log into **Shuffle** (shuffler.io) and create a new workflow named MyDFIR-AD-Project-2.0.  
2. Drag a **Webhook** trigger onto the canvas, rename it Splunk-Alert, and copy the generated Webhook URI.  
3. In Splunk Web, go to **Alerts**, edit the MyDFIR-Unauthorized-Successful-Login-RDP alert, and click **Add Actions** \> **Webhook**.  
4. Paste the Shuffle Webhook URI and save the alert.  
5. In Shuffle, click the **Start** button on the Webhook node to begin listening for incoming events.

*\[Insert Screenshot: The Shuffle canvas showing the active Webhook node alongside the Splunk Webhook configuration pane.\]*

### **2\. Set Up Slack Notifications**

1. Create a free Slack workspace (e.g., mydfir-projects) and establish a public channel named \#alerts.  
2. In your Shuffle workflow, drag the **Slack** app node onto the canvas and connect the Webhook node to it. Rename it Alert-Notification.  
3. Click **Authenticate**, log into Slack, and grant the Shuffle bot permission to access your workspace.  
4. Configure the Slack node parameters to format the alert using Shuffle runtime arguments:  
   * **Text Input:** Alert: $exec.result.search\_name  
     Time: $exec.result.\_time  
     User: $exec.result.user  
     Source IP: $exec.result.Source\_Network\_Address  
   * **Channel:** Paste your Slack Channel ID (located in the URL string when viewing the channel in a web browser).

*\[Insert Screenshot: The Slack node configuration in Shuffle displaying the mapped runtime arguments.\]*

### **3\. Configure Human-in-the-Loop (Email Approval)**

1. Drag a **User Input** trigger node into the workflow and connect the Slack node to it.  
2. Rename the node to User Action.  
3. Configure the question prompt: Would you like to disable the user?  
4. Set the **Notification Type** to **Email** and supply the designated SOC Analyst email address.

*\[Insert Screenshot: The User Input node configuration showing the specified prompt and email recipient.\]*

### **4\. Automate Active Directory Account Disabling**

1. Drag an **Active Directory** app node onto the canvas and connect the User Input node to it.  
2. Add a new authentication profile for your Domain Controller:  
   * **Server:** \<Domain\_Controller\_Public\_IP\>  
   * **Port:** 389 (Ensure TCP 389 is temporarily allowed on your cloud firewall for this lab).  
   * **Domain:** \<Your\_Domain\>  
   * **Logon User:** Administrator  
   * **Password:** \<Your\_Admin\_Password\>  
   * **Base DN:** The path to the Users container (e.g., CN=Users,DC=mydfir,DC=local).  
   * **Use SSL:** false  
3. Set the Action to **Disable User**.  
4. Set the Account Name field to dynamic input from the Splunk alert: $exec.result.user.

*\[Insert Screenshot: The Active Directory node configuration detailing the connection parameters and Disable User action.\]*

### **5\. Verify Action and Send Final Slack Update**

1. Drag a second **Active Directory** app node onto the canvas and connect it to the first AD node.  
2. Set the Action to **Get User-Attributes**, utilizing the identical authentication profile and dynamic Account Name ($exec.result.user). Include the Base DN in the Search Base field.  
3. Drag a final **Slack** node onto the canvas, connect it to the Get User-Attributes node, and rename it Update Notification.  
4. Click the connecting line between the second AD node and the final Slack node to create a condition. Set it to trigger only if the parsed userAccountControl attribute contains Account Disabled.  
5. Configure the final Slack node to post to the \#alerts channel with the text: Account $exec.result.user has been disabled.  
6. Start the workflow, trigger an RDP login alert, approve the email prompt, and verify that the account is successfully disabled in Active Directory and the final confirmation appears in Slack.

*\[Insert Screenshot: The completed Shuffle workflow depicting the entire SOAR pipeline from Webhook to Final Slack Notification.\]*

# 🚀 **DevOps Project: Book My Show App Deployment**  

Welcome to the **Book My Show App Deployment** project! This project demonstrates how to deploy a **Book My Show-clone application** using modern DevOps tools and practices, following a **DevSecOps** approach.  
_____________________________________________________________________________________________________________________________________________________________________________________________________
Step 1 : Launch Instance
____________________________________________________________________________________________________
- With the instance type t3.lagre

![Screenshot 2025-03-19 211549](https://github.com/user-attachments/assets/90751499-3731-40fc-8016-7f9464750d04)

- attached Security Group to the above instance is
Type                  Protocol   Port range                              
SMTP                  TCP           25 
(Used for sending emails between mail servers)

Custom TCP        TCP		3000-10000 
(Used by various applications, such as Node.js (3000), Grafana (3000), Jenkins (8080), and custom web applications.

HTTP                   TCP           80
Allows unencrypted web traffic. Used by web servers (e.g., Apache, Nginx) to serve websites over HTTP.

HTTPS                 TCP           443
Allows secure web traffic using SSL/TLS.

SSH                      TCP           22
Secure Shell (SSH) for remote server access.

Custom TCP         TCP           6443
Kubernetes API server port. Used for communication between kubectl, worker nodes, and the Kubernetes control plane.

SMTPS                 TCP           465
Secure Mail Transfer Protocol over SSL/TLS. Used for sending emails securely via SMTP with encryption.

Custom TCP         TCP           30000-32767
Kubernetes NodePort service range.

![Screenshot 2025-04-03 185034](https://github.com/user-attachments/assets/6089e086-6315-4525-be0b-aedf4b37fd7f)

- Connect the instance and type the command :
   - sudo apt update
------------------------------------------------------------------------------------------------ 
 Now we have to install jenkins and java firstly by following command :
     - vi Jenkins.sh ----> Paste the below content ---->

#!/bin/bash

# Install OpenJDK 17 JRE Headless
sudo apt install openjdk-17-jre-headless -y

# Download Jenkins GPG key
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
  https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key

# Add Jenkins repository to package manager sources
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null

# Update package manager repositories
sudo apt-get update

# Install Jenkins
sudo apt-get install jenkins -y

- sudo chmod +x jenkins.sh
- ./jenkins.sh
- sudosystemctl status jenkins
- cat
------------------------------------------------------------------------------------------------
Now we have to need install docker by using cmd :

vi docker.sh ----> Paste the below content ---->

#!/bin/bash

# Update package manager repositories
sudo apt-get update

# Install necessary dependencies
sudo apt-get install -y ca-certificates curl

# Create directory for Docker GPG key
sudo install -m 0755 -d /etc/apt/keyrings

# Download Docker's GPG key
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc

# Ensure proper permissions for the key
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add Docker repository to Apt sources
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package manager repositories
sudo apt-get update

sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 

- sudo chmod +x docker.sh
- ./docker.sh
- docker --version
- docker pull hello-world
- chmod 666 /var/run/docker.sock
- docker images
- docker login -u grishmai28
![Screenshot (229)](https://github.com/user-attachments/assets/b67b16b9-cb79-4136-b50a-097150551b26)


![Screenshot 2025-04-03 185518](https://github.com/user-attachments/assets/18171349-0366-4ea0-8a49-e1cf8a57776a)
![Screenshot (230)](https://github.com/user-attachments/assets/d3bfef93-55ca-4435-8fea-5626321636b8)

------------------------------------------------------------------------------------------------
Now install trivy on jenkins server

 vi trivy.sh ----> Paste the below commands ---->
#!/bin/bash
sudo apt-get install wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

- sudo chmod +x trivy.sh
- ./trivy.sh
- trivy --version
docker run -d --name sonar -p 9000:9000 sonarqube:Its-commumnity
docker images
docker ps
------------------------------------------------------------------------------------------------
Access SonarQube, after opening port 9000
Default username and Password: admin
Set new password

------------------------------------------------------------------------------------------------
Now install EKS cluster :
- firstly Attach policies to the user 
 AmazonEC2FullAccess, AmazonEKS_CNI_Policy, AmazonEKSClusterPolicy, AmazonEKSWorkerNodePolicy, AWSCloudFormationFullAccess, IAMFullAccess

Attach the below inline policy also for the same user
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "eks:*",
            "Resource": "*"
        }
    ]
}

- Create Access Keys for the user created
With this we have created the IAM User with appropriate permissions to create the EKS Cluster
- Install AWS CLI (to interact with AWS Account)
   - curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   - sudo apt install unzip
   - unzip awscliv2.zip
   - sudo ./aws/install
   - aws configure

- Configure aws by executing below command
   - aws configure 


- Install KubeCTL (to interact with K8S)
     - curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01- 
       05/bin/linux/amd64/kubectl
     - chmod +x ./kubectl
     - sudo mv ./kubectl /usr/local/bin
     - kubectl version --short --client


- Install EKS CTL (used to create EKS Cluster) 
     - curl --silent --location 
       "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname - 
       s)_amd64.tar.gz" | tar xz -C /tmp
     - sudo mv /tmp/eksctl /usr/local/bin
     - eksctl version
![Screenshot (235)](https://github.com/user-attachments/assets/3c71d3ef-6110-49e9-9078-629bce6bff95)
![Screenshot (236)](https://github.com/user-attachments/assets/057973ad-0b93-40bb-b32b-5f46b997746f)
![Screenshot (237)](https://github.com/user-attachments/assets/9448b29a-1b82-4904-816a-e98063d8b35f)


-  Create EKS Cluster
Execute the below commands as separate set
     - eksctl create cluster --name=kastro-eks \
                      --region=eu-north-1  \
                      --zones=eu-north-1a,eu-north-1b \
                      --version=1.30 \
                      --without-nodegroup

It will take 5-10 minutes to create the cluster
Goto EKS Console and verify the cluster.

  - eksctl utils associate-iam-oidc-provider \
    --region eu-north-1 \
    --cluster kastro-eks \
    --approve
![Screenshot (220)](https://github.com/user-attachments/assets/f819d651-6e57-4a2b-9759-d99f2232af3f)

The above command is crucial when setting up an EKS cluster because it enables IAM roles for service accounts (IRSA)
Amazon EKS uses OpenID Connect (OIDC) to authenticate Kubernetes service accounts with IAM roles.
Associating the IAM OIDC provider allows Kubernetes workloads (Pods) running in the cluster to assume IAM roles securely.
Without this, Pods in EKS clusters would require node-level IAM roles, which grant permissions to all Pods on a node.
Without this, these services will not be able to access AWS resources securely.

- Before executing the below command, in the 'ssh-public-key' keep the  '<PEM FILE NAME>' (dont give .pem. Just give the pem file name) which was used to create Jenkins Server

eksctl create nodegroup --cluster=kastro-eks \
                       --region=eu-north-1  \
                       --name=node2 \
                       --node-type=t3.medium \
                       --nodes=3 \
                       --nodes-min=2 \
                       --nodes-max=4 \
                       --node-volume-size=20 \
                       --ssh-access \
                       --ssh-public-key=Kastro \
                       --managed \
                       --asg-access \
                       --external-dns-access \
                       --full-ecr-access \
                       --appmesh-access \
                       --alb-ingress-access

It will take 5-10 minutes 

-  For internal communication b/w control plane and worker nodes, open 'all traffic' in the security group of EKS Cluster
![Screenshot 2025-04-03 185534](https://github.com/user-attachments/assets/31dedf71-37da-404b-84bd-672c9349a7b8)
************************************
Step-2 : Setup the Jenkins
![Screenshot (222)](https://github.com/user-attachments/assets/a9fbaa52-fcd8-4f49-9257-2ee88294194d)
![Screenshot (223)](https://github.com/user-attachments/assets/bf35d10f-fa0b-4ec8-b3f6-403df82a691e)
![Screenshot (225)](https://github.com/user-attachments/assets/a20040ee-bc30-4dad-838d-0f4d8a4c1262)
![Screenshot (226)](https://github.com/user-attachments/assets/0a58e0ed-a766-4fd0-881e-f8948cd3710e)
![Screenshot (227)](https://github.com/user-attachments/assets/aeb509b4-12a0-4a27-a05d-9a026e032c08)

-  Plugins installation
Install below plugins;
Eclipse Temurin Installer, SonarQube scanner, NodeJS, Docker, Docker Commons, Docker Pipeline, Docker API, docker-build-step, OWASP dependency check, Pipeline stage view, Email Extension Template, Kubernetes, Kubernetes CLI, Kubernetes Client API, Kubernetes Credentials, Config File Provider, Prometheus metrics

- SonarQube Token Creation
Configure the SonarQube server;
Token: squ_69eb05b41575c699579c6ced901eaafae66d63a2

- Creation of Credentials

- Tools Configuration
  
- System Configuration in Jenkins
![Screenshot 2025-04-03 190044](https://github.com/user-attachments/assets/a1d692c6-5ffd-42b2-b428-ef2dcbb5c03e)

************************************
Step 3: Email Integration
************************************
As soon as the build happens, i need to get an email notification to do that we have to configure our email.
Goto Gmail ---> Click on Icon on top right ---> Click on 'Your google account' ---> in search box at top, search for 'App  Passwords' and click on it, Enter password of gmail ---> Next ---> App name: jenkins ---> Create ---> You can see the password (ex: fxssvxsvfbartxnt) ---> Copy it ---> Make sure to remove the spaces in the password. Lets configure this password in Jenkins.

Goto the Jenkins console ---> Manage Jenkins ---> Security ---> Credentials ---> Under 'Stores scoped to Jenkins', Click on 'Global' under 'Domains' ---> Add credentials ---> A dia ---> Kind: Username with Password, Scope: Global, Username: <ProvideEmail ID>, Password: <PasteTheToken>, ID: email-creds, Description: email-creds ---> Create ---> You can see the email credentials got created.

Manage Jenkins ---> System ---> Scroll down to 'Extended Email Notification' ---> SMTP Server: smtp.gmail.com ---> SMTP Port: 465, Click on 'Advanced'  ---> Credentials: Select 'email creds' from drop down, 'Check' Use SSL and Use OAuth 2.0, Default content type: HTML

Scroll down to 'Email Notification' ---> SMTP Server: smtp.gmail.com ---> Click on 'Advanced'  ---> 'Check' Use SMTP Authentication, Username: <ProvideEmailID>, Password: <PasteThePasswordToken>, 'Check' Use SSL, SMTP Port: 465, Reply-to-email: <ProvideEmail>, Charset: UTF-8,, Check 'Test configuration by sending test e-mail', Test Email Recepient: <provide-email-id>, Click on 'Test Configuration' ---> You can see 'email sent' ---> Goto email and check for test email

Lets make another configuration to get an email when build fails/success ---> Goto 'Default Triggers' drop down (If you cannot find this, try searching using control+f ---> 'Check' Always, Failure-Any, Success ---> Apply ---> Save 

-------------------
Install NPM
-------------------
apt install npm
Step 5: Create Pipeline Job
************************************
Before pasting the pipeline script, do the following changes in the script
1. In the stage 'Tag and Push to DockerHub', give your docker-hub username. Similar thing you should do in 'Deploy to container' stage.
2. In post actions stage in pipeline, make sure to give the email id you have configured in jenkins.

&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
BMS - Script (Without K8S Stage)
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
pipeline {
    agent any
    tools {
        jdk 'jdk17'
        nodejs 'node23'
    }
    environment {
        SCANNER_HOME = tool 'sonar-scanner'
    }
    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }
        stage('Checkout from Git') {
            steps {
git branch: 'main', url: 'https://github.com/grishmaingle/Deployment-of-Book-My-Show-Application.git'
                sh 'ls -la'  // Verify files after checkout
            }
        }
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh ''' 
                    $SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=BMS \
                    -Dsonar.projectKey=BMS 
                    '''
                }
            }
        }
        stage('Quality Gate') {
            steps {
                script {
                    waitForQualityGate abortPipeline: false, credentialsId: 'Sonar-token'
                }
            }
        }
        stage('Install Dependencies') {
            steps {
                sh '''
                cd bookmyshow-app
                ls -la  # Verify package.json exists
                if [ -f package.json ]; then
                    rm -rf node_modules package-lock.json  # Remove old dependencies
                    npm install  # Install fresh dependencies
                else
                    echo "Error: package.json not found in bookmyshow-app!"
                    exit 1
                fi
                '''
            }
        }
        stage('Trivy FS Scan') {
            steps {
                sh 'trivy fs . > trivyfs.txt'
            }
        }
        stage('Docker Build & Push') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'docker', toolName: 'docker') {
                        sh ''' 
                        echo "Building Docker image..."
                        docker build --no-cache -t kastrov/bms:latest -f bookmyshow-app/Dockerfile bookmyshow-app
                        echo "Pushing Docker image to registry..."
                        docker push kastrov/bms:latest
                        '''
                    }
                }
            }
        }
        stage('Deploy to Container') {
            steps {
                sh ''' 
                echo "Stopping and removing old container..."
                docker stop bms || true
                docker rm bms || true
                echo "Running new container on port 3000..."
                docker run -d --restart=always --name bms -p 3000:3000 kastrov/bms:latest
                echo "Checking running containers..."
                docker ps -a
                echo "Fetching logs..."
                sleep 5  # Give time for the app to start
                docker logs bms
                '''
            }
        }
    }
    post {
        always {
            emailext attachLog: true,
                subject: "'${currentBuild.result}'",
                body: "Project: ${env.JOB_NAME}<br/>" +
                      "Build Number: ${env.BUILD_NUMBER}<br/>" +
                      "URL: ${env.BUILD_URL}<br/>",
                to: 'grishmaingle138@gmail.com',
                attachmentsPattern: 'trivyfs.txt,trivyimage.txt'
        }
    }
}

![Screenshot (238)](https://github.com/user-attachments/assets/4f3aeeb1-bd36-4b57-aae1-9fb0e3ebfae5)
![Screenshot (239)](https://github.com/user-attachments/assets/dade0e59-66a8-42d3-aa12-741b1786b453)
![Screenshot (248)](https://github.com/user-attachments/assets/48e233e1-92ad-4e8a-a046-a7986f0c5cd0)

Access the BMS App using Public IP of BMS-Server
************************************************************************************************************************************************************************************************

Step 6: Monitoring the application
************************************
Launch Ubuntu VM, 22.04, t2.medium, 
Name the VM as Monitoring Server

-  Connect to the Monitoring Server VM (Execute in Monitoring Server VM)
Create a dedicated Linux user sometimes called a 'system' account for Prometheus
sudo apt update

sudo useradd \
    --system \
    --no-create-home \
    --shell /bin/false prometheus

With the above command, we have created a 'Prometheus' user

Explanation of above command
–system – Will create a system account.
–no-create-home – We don’t need a home directory for Prometheus or any other system accounts in our case.
–shell /bin/false – It prevents logging in as a Prometheus user.
Prometheus – Will create a Prometheus user and a group with the same name.
![Screenshot (240)](https://github.com/user-attachments/assets/c6005a9b-82aa-4b0c-b1c3-caf5a11e0285)

![Screenshot 2025-04-04 000524](https://github.com/user-attachments/assets/de87bb5d-0153-4ad1-b3fc-2cd9eb43b971)


-  Download the Prometheus
sudo wget https://github.com/prometheus/prometheus/releases/download/v2.47.1/prometheus-2.47.1.linux-amd64.tar.gz
tar -xvf prometheus-2.47.1.linux-amd64.tar.gz
sudo mkdir -p /data /etc/prometheus
cd prometheus-2.47.1.linux-amd64/

Move the Prometheus binary and a promtool to the /usr/local/bin/. promtool is used to check configuration files and Prometheus rules.
sudo mv prometheus promtool /usr/local/bin/

Move console libraries to the Prometheus configuration directory
sudo mv consoles/ console_libraries/ /etc/prometheus/

Move the example of the main Prometheus configuration file
sudo mv prometheus.yml /etc/prometheus/prometheus.yml

Set the correct ownership for the /etc/prometheus/ and data directory
sudo chown -R prometheus:prometheus /etc/prometheus/ /data/

Delete the archive and a Prometheus tar.gz file 
cd
You are in ~ path
rm -rf prometheus-2.47.1.linux-amd64.tar.gz

prometheus --version
You will see as "version 2.47.1"

prometheus --help

We’re going to use Systemd, which is a system and service manager for Linux operating systems. For that, we need to create a Systemd unit configuration file.
sudo vi /etc/systemd/system/prometheus.service ---> Paste the below content ---->

[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5
[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/data \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090 \
  --web.enable-lifecycle
[Install]
WantedBy=multi-user.target

 ----> esc ----> :wq ----> 

To automatically start the Prometheus after reboot run the below command
sudo systemctl enable prometheus

Start the Prometheus
sudo systemctl start prometheus

Check the status of Prometheus
sudo systemctl status prometheus

Open Port No. 9090 for Monitoring Server VM and Access Prometheus
<public-ip:9090>

If it doesn't work, in the web link of browser, remove 's' in 'https'. Keep only 'http' and now you will be able to see.
You can see the Prometheus console.
Click on 'Status' dropdown ---> Click on 'Targets' ---> You can see 'Prometheus (1/1 up)' ----> It scrapes itself every 15 seconds by default.

- Install Node Exporter (Execute in Monitoring Server VM)
You are in ~ path now

Create a system user for Node Exporter and download Node Exporter:
sudo useradd --system --no-create-home --shell /bin/false node_exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz

Extract Node Exporter files, move the binary, and clean up:
tar -xvf node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
rm -rf node_exporter*

node_exporter --version

Create a systemd unit configuration file for Node Exporter:
sudo vi /etc/systemd/system/node_exporter.service

Add the following content to the node_exporter.service file:
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/node_exporter --collector.logind

[Install]
WantedBy=multi-user.target

Note: Replace --collector.logind with any additional flags as needed.

Enable and start Node Exporter:
sudo systemctl enable node_exporter
sudo systemctl start node_exporter

Verify the Node Exporter's status:
sudo systemctl status node_exporter
You can see "active (running)" in green colour
Press control+c to come out of the file

-  Configure Prometheus Plugin Integration

As of now we created Prometheus service, but we need to add a job in order to fetch the details by node exporter. So for that we need to create 2 jobs, one with 'node exporter' and the other with 'jenkins' as shown below;

Integrate Jenkins with Prometheus to monitor the CI/CD pipeline.

Prometheus Configuration:

To configure Prometheus to scrape metrics from Node Exporter and Jenkins, you need to modify the prometheus.yml file. 
The path of prometheus.yml is; cd /etc/prometheus/ ----> ls -l ----> You can see the "prometheus.yml" file ----> sudo vi prometheus.yml ----> You will see the content and also there is a default job called "Prometheus" Paste the below content at the end of the file;

  - job_name: 'node_exporter'
    static_configs:
      - targets: ['<MonitoringVMip>:9100']

  - job_name: 'jenkins'
    metrics_path: '/prometheus'
    static_configs:
      - targets: ['<your-jenkins-ip>:<your-jenkins-port>']



 In the above, replace <your-jenkins-ip> and <your-jenkins-port> with the appropriate IPs ----> esc ----> :wq
Also replace the public ip of monitorting VM. Dont change 9100. Even though the Monitoring server is running on 9090, dont change 9100 in the above script

Check the validity of the configuration file:
promtool check config /etc/prometheus/prometheus.yml
You should see "SUCCESS" when you run the above command, it means every configuration made so far is good.

Reload the Prometheus configuration without restarting:
curl -X POST http://localhost:9090/-/reload

Access Prometheus in browser (if already opened, just reload the page):
http://<your-prometheus-ip>:9090/targets

For Node Exporter you will see (0/1) in red colour. To resolve this, open Port number 9100 for Monitoring VM 

You should now see "Jenkins (1/1 up)" "node exporter (1/1 up)" and "prometheus (1/1 up)" in the prometheus browser.
Click on "showmore" next to "jenkins." You will see a link. Open the link in new tab, to see the metrics that are getting scraped

-------------------------------------------------------------------
-  Install Grafana (Execute in Monitoring Server VM)
-------------------------------------------------------------------
You are currently in /etc/Prometheus path.
![Screenshot 2025-04-04 000734](https://github.com/user-attachments/assets/948bfb98-16ff-4690-b87f-af25faf4a933)

Install Grafana on Monitoring Server;

Step 1: Install Dependencies:
First, ensure that all necessary dependencies are installed:
sudo apt-get update
sudo apt-get install -y apt-transport-https software-properties-common

Step 2: Add the GPG Key:
cd ---> You are now in ~ path
Add the GPG key for Grafana:
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -

You should see OK when executed the above command.

Step 3: Add Grafana Repository:
Add the repository for Grafana stable releases:
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list

Step 4: Update and Install Grafana:
Update the package list and install Grafana:
sudo apt-get update
sudo apt-get -y install grafana

Step 5: Enable and Start Grafana Service:
To automatically start Grafana after a reboot, enable the service:
sudo systemctl enable grafana-server

Start Grafana:
sudo systemctl start grafana-server

Step 6: Check Grafana Status:
Verify the status of the Grafana service to ensure it's running correctly:
sudo systemctl status grafana-server

You should see "Active (running)" in green colour
Press control+c to come out

Step 7: Access Grafana Web Interface:
The default port for Grafana is 3000
http://<monitoring-server-ip>:3000

Default id and password is "admin"
You can Set new password or you can click on "skip now".
Click on "skip now" (If you want you can create the password)

You will see the Grafana dashboard

-  Adding Data Source in Grafana
The first thing that we have to do in Grafana is to add the data source
Add the data source;


-  Adding Dashboards in Grafana 
(URL: https://grafana.com/grafana/dashboards/1860-node-exporter-full/) 
Lets add another dashboard for Jenkins;
(URL: https://grafana.com/grafana/dashboards/9964-jenkins-performance-and-health-overview/)

Click on Dashboards in the left pane, you can see both the dashboards you have just added.
![Screenshot 2025-04-04 000813](https://github.com/user-attachments/assets/fd5675f6-38da-4a3f-a99e-7f8a9f4ae5a9)
![Screenshot 2025-04-04 001157](https://github.com/user-attachments/assets/c8108150-43da-46a6-89df-5c0ded787d61)

Final output : 

![Screenshot (231)](https://github.com/user-attachments/assets/d7676cb9-221f-4b9f-9718-72062464d1de)

![Screenshot (246)](https://github.com/user-attachments/assets/c7c88812-6621-4cb7-9090-f8f9efa30854)

![Screenshot (232)](https://github.com/user-attachments/assets/f43b9ee8-4db5-40eb-8e73-c3d6a55ed120)

![Screenshot (233)](https://github.com/user-attachments/assets/2df86a85-ad23-4374-84b3-6a141d5b7de0)

![Screenshot (234)](https://github.com/user-attachments/assets/8271fa95-e945-41bb-b44a-a0b7d7c5a44a)

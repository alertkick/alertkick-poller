// ============================================================================
// DEPLOYMENT STRATEGY
// ============================================================================
//   develop branch → build → push to ECR (develop-<sha>) → deploy to STAGING
//   git tag         → build → push to ECR (<tag>)         → deploy to PRODUCTION
//
// Image: ecr.alertkick.com/ak/alertkick-poller
//
// Note: managed pollers run on be-app nodes via fleet deploy-service.
// Customer on-prem pollers use the same image but pull it themselves and
// run via their own docker-compose.
// ============================================================================

pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    triggers {
        githubPush()
    }

    environment {
        GIT_HASH = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
        BUILD_TIME = sh(script: 'date -u +%Y-%m-%dT%H:%M:%SZ', returnStdout: true).trim()
        GIT_BRANCH_NAME = sh(script: 'git rev-parse --abbrev-ref HEAD', returnStdout: true).trim()
        IMAGE_TAG = "${env.TAG_NAME ?: 'develop-' + GIT_HASH}"
        DOCKER_REPO = "ecr.alertkick.com/ak/alertkick-poller"
        DOCKER_CREDENTIALS = credentials('docker-login-credentials')
        SUPERADMIN_URL = "http://superadmin.ssidhu.io:3002"
        DEPLOY_NODE_TYPE = "be-app"
    }

    stages {
        stage('Build Docker Image') {
            steps {
                sh """
                    docker build \\
                        --build-arg VERSION=${IMAGE_TAG} \\
                        --build-arg GIT_HASH=${GIT_HASH} \\
                        --build-arg GIT_BRANCH=${GIT_BRANCH_NAME} \\
                        --build-arg BUILD_TIME=${BUILD_TIME} \\
                        -t ${DOCKER_REPO}:${IMAGE_TAG} .
                """
            }
        }

        stage('Push Docker Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-login-credentials', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                    sh """
                        DOCKER_CFG=\$(mktemp -d)
                        echo \$DOCKER_PASSWORD | docker --config \$DOCKER_CFG login https://ecr.alertkick.com -u \$DOCKER_USERNAME --password-stdin
                        docker --config \$DOCKER_CFG push ${DOCKER_REPO}:${IMAGE_TAG}
                        docker tag ${DOCKER_REPO}:${IMAGE_TAG} ${DOCKER_REPO}:latest
                        docker --config \$DOCKER_CFG push ${DOCKER_REPO}:latest
                        rm -rf \$DOCKER_CFG
                    """
                }
            }
        }

        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                sh '''
                    set -eu
                    PAYLOAD=$(printf '{"service_name":"poller","image_tag":"%s","node_type":"%s"}' "$IMAGE_TAG" "$DEPLOY_NODE_TYPE")
                    echo "Deploying to stg: $PAYLOAD"
                    curl --fail-with-body -sS --max-time 900 -X POST "${SUPERADMIN_URL}/fleet-api/environments/stg/deploy-service" -H "Content-Type: application/json" -d "$PAYLOAD"
                '''
            }
        }

        stage('Deploy to Production') {
            when {
                buildingTag()
            }
            steps {
                sh '''
                    set -eu
                    PAYLOAD=$(printf '{"service_name":"poller","image_tag":"%s","node_type":"%s"}' "$IMAGE_TAG" "$DEPLOY_NODE_TYPE")
                    echo "Deploying to prod: $PAYLOAD"
                    curl --fail-with-body -sS --max-time 900 -X POST "${SUPERADMIN_URL}/fleet-api/environments/prod/deploy-service" -H "Content-Type: application/json" -d "$PAYLOAD"
                '''
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}

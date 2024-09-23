const {KmsKeyringNode, buildClient, CommitmentPolicy} = require('@aws-crypto/client-node');
const url = require('url');
const https = require('node:https');
const config = require('./config');

const kmsClient = buildClient(
    CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)

let hookUrl;
const baseSlackMessage = {}


function postMessage(message, callback) {
    const body = JSON.stringify(message);
    const options = url.parse(hookUrl);
    options.method = 'POST';
    options.headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
    };

    const postReq = https.request(options, function (res) {
        const chunks = [];
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            return chunks.push(chunk);
        });
        res.on('end', function () {
            const body = chunks.join('');
            if (callback) {
                callback({
                    body: body,
                    statusCode: res.statusCode,
                    statusMessage: res.statusMessage
                });
            }
        });
        return res;
    });

    postReq.write(body);
    postReq.end();
}

function handleElasticBeanstalk(event, context) {
    const timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
    const subject = event.Records[0].Sns.Subject || "AWS Elastic Beanstalk Notification";
    const message = event.Records[0].Sns.Message;

    const stateRed = message.indexOf(" to RED");
    const stateSevere = message.indexOf(" to Severe");
    const butWithErrors = message.indexOf(" but with errors");
    const noPermission = message.indexOf("You do not have permission");
    const failedDeploy = message.indexOf("Failed to deploy application");
    const failedConfig = message.indexOf("Failed to deploy configuration");
    const failedQuota = message.indexOf("Your quota allows for 0 more running instance");
    const unsuccessfulCommand = message.indexOf("Unsuccessful command execution");

    const stateYellow = message.indexOf(" to YELLOW");
    const stateDegraded = message.indexOf(" to Degraded");
    const stateInfo = message.indexOf(" to Info");
    const removedInstance = message.indexOf("Removed instance ");
    const addingInstance = message.indexOf("Adding instance ");
    const abortedOperation = message.indexOf(" aborted operation.");
    const abortedDeployment = message.indexOf("some instances may have deployed the new application version");

    let color = "good";

    if (stateRed != -1 || stateSevere != -1 || butWithErrors != -1 || noPermission != -1 || failedDeploy != -1 || failedConfig != -1 || failedQuota != -1 || unsuccessfulCommand != -1) {
        color = "danger";
    }
    if (stateYellow != -1 || stateDegraded != -1 || stateInfo != -1 || removedInstance != -1 || addingInstance != -1 || abortedOperation != -1 || abortedDeployment != -1) {
        color = "warning";
    }

    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "fields": [
                    {"title": "Subject", "value": event.Records[0].Sns.Subject, "short": false},
                    {"title": "Message", "value": message, "short": false}
                ],
                "color": color,
                "ts": timestamp
            }
        ]
    };

    return _.merge(slackMessage, baseSlackMessage);
}

function handleCodeDeploy(event, context) {
    const subject = "AWS CodeDeploy Notification";
    const timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
    const snsSubject = event.Records[0].Sns.Subject;
    const fields = [];
    let color = "warning";
    let message;

    try {
        message = JSON.parse(event.Records[0].Sns.Message);

        if (message.status === "SUCCEEDED") {
            color = "good";
        } else if (message.status === "FAILED") {
            color = "danger";
        }
        fields.push({"title": "Message", "value": snsSubject, "short": false});
        fields.push({"title": "Deployment Group", "value": message.deploymentGroupName, "short": true});
        fields.push({"title": "Application", "value": message.applicationName, "short": true});
        fields.push({
            "title": "Status Link",
            "value": "https://console.aws.amazon.com/codedeploy/home?region=" + message.region + "#/deployments/" + message.deploymentId,
            "short": false
        });
    } catch (e) {
        color = "good";
        message = event.Records[0].Sns.Message;
        fields.push({"title": "Message", "value": snsSubject, "short": false});
        fields.push({"title": "Detail", "value": message, "short": false});
    }


    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "color": color,
                "fields": fields,
                "ts": timestamp
            }
        ]
    };

    return _.merge(slackMessage, baseSlackMessage);
}

function handleCodePipeline(event, context) {
    const subject = "AWS CodePipeline Notification";
    const timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
    const fields = [];
    let message;
    let color = "warning";
    let changeType = "";

    try {
        message = JSON.parse(event.Records[0].Sns.Message);
        detailType = message['detail-type'];

        if (detailType === "CodePipeline Pipeline Execution State Change") {
            changeType = "";
        } else if (detailType === "CodePipeline Stage Execution State Change") {
            changeType = "STAGE " + message.detail.stage;
        } else if (detailType === "CodePipeline Action Execution State Change") {
            changeType = "ACTION";
        }

        if (message.detail.state === "SUCCEEDED") {
            color = "good";
        } else if (message.detail.state === "FAILED") {
            color = "danger";
        }
        header = message.detail.state + ": CodePipeline " + changeType;
        fields.push({"title": "Message", "value": header, "short": false});
        fields.push({"title": "Pipeline", "value": message.detail.pipeline, "short": true});
        fields.push({"title": "Region", "value": message.region, "short": true});
        fields.push({
            "title": "Status Link",
            "value": "https://console.aws.amazon.com/codepipeline/home?region=" + message.region + "#/view/" + message.detail.pipeline,
            "short": false
        });
    } catch (e) {
        color = "good";
        message = event.Records[0].Sns.Message;
        header = message.detail.state + ": CodePipeline " + message.detail.pipeline;
        fields.push({"title": "Message", "value": header, "short": false});
        fields.push({"title": "Detail", "value": message, "short": false});
    }


    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "color": color,
                "fields": fields,
                "ts": timestamp
            }
        ]
    };

    return _.merge(slackMessage, baseSlackMessage);
}

function handleElasticache(event, context) {
    const subject = "AWS ElastiCache Notification"
    const message = JSON.parse(event.Records[0].Sns.Message);
    const timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
    const region = event.Records[0].EventSubscriptionArn.split(":")[3];
    const color = "good";
    let eventname, nodename;

    for (let key in message) {
        eventname = key;
        nodename = message[key];
        break;
    }

    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "color": color,
                "fields": [
                    {"title": "Event", "value": eventname.split(":")[1], "short": true},
                    {"title": "Node", "value": nodename, "short": true},
                    {
                        "title": "Link to cache node",
                        "value": "https://console.aws.amazon.com/elasticache/home?region=" + region + "#cache-nodes:id=" + nodename + ";nodes",
                        "short": false
                    }
                ],
                "ts": timestamp
            }
        ]
    };
    return _.merge(slackMessage, baseSlackMessage);
}

function handleCloudWatch(event, context) {
    const timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
    const message = JSON.parse(event.Records[0].Sns.Message);
    const region = event.Records[0].EventSubscriptionArn.split(":")[3];
    const subject = "AWS CloudWatch Notification";
    const alarmName = message.AlarmName;
    const metricName = message.Trigger.MetricName;
    const oldState = message.OldStateValue;
    const newState = message.NewStateValue;
    const alarmDescription = message.AlarmDescription;

    const trigger = message.Trigger;
    let color = "warning";

    if (message.NewStateValue === "ALARM") {
        color = "danger";
    } else if (message.NewStateValue === "OK") {
        color = "good";
    }

    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "color": color,
                "fields": [
                    {"title": "Alarm Name", "value": alarmName, "short": true},
                    {"title": "Alarm Description", "value": alarmDescription, "short": false},
                    {
                        "title": "Trigger",
                        "value": trigger.Statistic + " "
                            + metricName + " "
                            + trigger.ComparisonOperator + " "
                            + trigger.Threshold + " for "
                            + trigger.EvaluationPeriods + " period(s) of "
                            + trigger.Period + " seconds.",
                        "short": false
                    },
                    {"title": "Old State", "value": oldState, "short": true},
                    {"title": "Current State", "value": newState, "short": true},
                    {
                        "title": "Link to Alarm",
                        "value": "https://console.aws.amazon.com/cloudwatch/home?region=" + region + "#alarm:alarmFilter=ANY;name=" + encodeURIComponent(alarmName),
                        "short": false
                    }
                ],
                "ts": timestamp
            }
        ]
    };
    return _.merge(slackMessage, baseSlackMessage);
}

function handleAutoScaling(event, context) {
    const subject = "AWS AutoScaling Notification"
    const message = JSON.parse(event.Records[0].Sns.Message);
    const timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
    const color = "good";
    let eventname, nodename;

    for (key in message) {
        eventname = key;
        nodename = message[key];
        break;
    }
    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "color": color,
                "fields": [
                    {"title": "Message", "value": event.Records[0].Sns.Subject, "short": false},
                    {"title": "Description", "value": message.Description, "short": false},
                    {"title": "Event", "value": message.Event, "short": false},
                    {"title": "Cause", "value": message.Cause, "short": false}

                ],
                "ts": timestamp
            }
        ]
    };
    return _.merge(slackMessage, baseSlackMessage);
}

function handleCatchAll(event, context) {
    const record = event.Records[0]
    const subject = record.Sns.Subject
    const timestamp = new Date(record.Sns.Timestamp).getTime() / 1000;
    const message = JSON.parse(record.Sns.Message)
    let color = "warning";

    if (message.NewStateValue === "ALARM") {
        color = "danger";
    } else if (message.NewStateValue === "OK") {
        color = "good";
    }

    // Add all of the values from the event message to the Slack message description
    let description = ""
    for (key in message) {

        const renderedMessage = typeof message[key] === 'object'
            ? JSON.stringify(message[key])
            : message[key]

        description = description + "\n" + key + ": " + renderedMessage
    }

    const slackMessage = {
        text: "*" + subject + "*",
        attachments: [
            {
                "color": color,
                "fields": [
                    {"title": "Message", "value": record.Sns.Subject, "short": false},
                    {"title": "Description", "value": description, "short": false}
                ],
                "ts": timestamp
            }
        ]
    }

    return _.merge(slackMessage, baseSlackMessage);
}

function processEvent(event, context) {
    console.log("sns received:" + JSON.stringify(event, null, 2));
    const eventSubscriptionArn = event.Records[0].EventSubscriptionArn;
    const eventSnsSubject = event.Records[0].Sns.Subject || 'no subject';
    const eventSnsMessageRaw = event.Records[0].Sns.Message;

    let eventSnsMessage = null;
    try {
        eventSnsMessage = JSON.parse(eventSnsMessageRaw);
    } catch (e) {
    }

    let slackMessage;
    if (eventSubscriptionArn.indexOf(config.services.codepipeline.match_text) > -1 || eventSnsSubject.indexOf(config.services.codepipeline.match_text) > -1 || eventSnsMessageRaw.indexOf(config.services.codepipeline.match_text) > -1) {
        console.log("processing codepipeline notification");
        slackMessage = handleCodePipeline(event, context)
    } else if (eventSubscriptionArn.indexOf(config.services.elasticbeanstalk.match_text) > -1 || eventSnsSubject.indexOf(config.services.elasticbeanstalk.match_text) > -1 || eventSnsMessageRaw.indexOf(config.services.elasticbeanstalk.match_text) > -1) {
        console.log("processing elasticbeanstalk notification");
        slackMessage = handleElasticBeanstalk(event, context)
    } else if (eventSnsMessage && 'AlarmName' in eventSnsMessage && 'AlarmDescription' in eventSnsMessage) {
        console.log("processing cloudwatch notification");
        slackMessage = handleCloudWatch(event, context);
    } else if (eventSubscriptionArn.indexOf(config.services.codedeploy.match_text) > -1 || eventSnsSubject.indexOf(config.services.codedeploy.match_text) > -1 || eventSnsMessageRaw.indexOf(config.services.codedeploy.match_text) > -1) {
        console.log("processing codedeploy notification");
        slackMessage = handleCodeDeploy(event, context);
    } else if (eventSubscriptionArn.indexOf(config.services.elasticache.match_text) > -1 || eventSnsSubject.indexOf(config.services.elasticache.match_text) > -1 || eventSnsMessageRaw.indexOf(config.services.elasticache.match_text) > -1) {
        console.log("processing elasticache notification");
        slackMessage = handleElasticache(event, context);
    } else if (eventSubscriptionArn.indexOf(config.services.autoscaling.match_text) > -1 || eventSnsSubject.indexOf(config.services.autoscaling.match_text) > -1 || eventSnsMessageRaw.indexOf(config.services.autoscaling.match_text) > -1) {
        console.log("processing autoscaling notification");
        slackMessage = handleAutoScaling(event, context);
    } else {
        slackMessage = handleCatchAll(event, context);
    }

    postMessage(slackMessage, function (response) {
        if (response.statusCode < 400) {
            console.info('message posted successfully');
            context.succeed();
        } else if (response.statusCode < 500) {
            console.error("error posting message to slack API: " + response.statusCode + " - " + response.statusMessage);
            // Don't retry because the error is due to a problem with the request
            context.succeed();
        } else {
            // Let Lambda retry
            context.fail("server error when processing message: " + response.statusCode + " - " + response.statusMessage);
        }
    });
}

exports.handler = function (event, context) {
    if (hookUrl) {
        processEvent(event, context);
    } else if (config.unencryptedHookUrl) {
        hookUrl = config.unencryptedHookUrl;
        processEvent(event, context);
    } else if (config.kmsEncryptedHookUrl && config.kmsEncryptedHookUrl !== '<kmsEncryptedHookUrl>') {
        const encryptedBuf = new Buffer(config.kmsEncryptedHookUrl, 'base64');
        const cipherText = {CiphertextBlob: encryptedBuf};

        const kmsKeyring = new KmsKeyringNode();
        kmsClient
            .decrypt(kmsKeyring, cipherText, )
            .then(({ plaintext }) => {
                hookUrl = "https://" + plaintext.toString('ascii');
                processEvent(event, context);
            })
            .catch(err => {
                console.error("decrypt error: " + err);
                processEvent(event, context);
            });
    } else {
        context.fail('hook url has not been set.');
    }
};

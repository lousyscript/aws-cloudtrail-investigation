# Investigating My Own AWS Misconfigurations with CloudTrail

In earlier labs I deliberately created misconfigurations on AWS (public S3 bucket, SSH open to the internet, broken routing, an over-permissive IAM role). This project goes back through **CloudTrail Event history** and reconstructs what happened from the logs alone, the way an investigator would.

**Services used:** CloudTrail (Event history), EC2, S3, IAM
**Region:** eu-north-1 (Stockholm). IAM events are logged in us-east-1.
**Time zone:** all times are UTC.

> Account ID, access key IDs, and IP addresses are redacted in every screenshot. I did not publish the raw CloudTrail export, since it contains them.

## Summary of findings

| Finding | Evidence | Window |
|---|---|---|
| Public S3 bucket | `PutBucketPolicy` with `Principal: "*"` | 5 min 41 s |
| SSH open to `0.0.0.0/0` | `ModifySecurityGroupRules` | 53 min 2 s |
| Internet route removed | `DeleteRoute` then `CreateRoute` | 42 s |
| Role denied a bucket listing | `ListBuckets` with `AccessDenied` | n/a |
| Console user without MFA | `"mfaAuthenticated": "false"` | n/a |

## 1. Public S3 bucket (Nov 10)

| Time | Event | What it did |
|---|---|---|
| 12:08:04 | `PutBucketPublicAccessBlock` (all four settings `false`) | Turned the safety net off |
| 12:17:34 | `PutBucketPolicy` with `"Principal": "*"`, `s3:GetObject` | **Objects became publicly readable** |
| 12:23:15 | `PutBucketPublicAccessBlock` (all four settings `true`) | **Public access blocked again** |
| 12:42:25 | `PutBucketPolicy` allowing only `cloudfront.amazonaws.com` with a `SourceArn` condition | Private bucket, served through CloudFront (OAC) |

The bucket was publicly readable for about **5 minutes 41 seconds**. Re-enabling Block Public Access ended the exposure even though the public policy was still attached, because the setting overrides it.

Screenshots:
- `screenshots/01-public-access-block-off.png`
- `screenshots/02-public-policy-applied.png`
- `screenshots/03-public-access-block-on.png`
- `screenshots/04-cloudfront-bucket-policy.png`

## 2. SSH open to the internet (Nov 11-12)

| Time | Source | Event |
|---|---|---|
| Nov 11, 23:16:29 | Console, my home IP | `ModifySecurityGroupRules`: SSH (22) source changed to **`0.0.0.0/0`** |
| Nov 11, 23:22:56 | SSH log on the instance | An unknown IP connected to port 22 and closed the connection without logging in |
| Nov 12, 00:09:31 | Console, my new home IP | `ModifySecurityGroupRules`: SSH (22) source changed to **a single `/32`** |

- Same rule ID in both events, so I edited one rule in place. That's why CloudTrail shows `ModifySecurityGroupRules` and not an authorize/revoke pair.
- Exposure window: **53 minutes 2 seconds**.
- The scanner connected **6 minutes 27 seconds** after the rule opened. The timestamp comes from the instance's SSH log (`journalctl -u sshd`), not from CloudTrail, which doesn't record network connections. I compared the two by hand, with the instance clock on UTC.
- My own SSH logins from my new IP at 23:53 only worked because the rule was still open to the world.
- Key-only login meant the scanner couldn't get in, but the exposure was real.

Screenshots:
- `screenshots/05-ssh-opened.png`
- `screenshots/06-ssh-restricted.png`

## 3. Routing break test (Nov 14)

| Time | Event |
|---|---|
| 21:47:00 | `DeleteRoute`: `0.0.0.0/0` removed from the public route table |
| 21:47:42 | `CreateRoute`: `0.0.0.0/0` to the internet gateway restored |

I removed the internet route on purpose to prove that routing and security groups are separate layers. SSH and HTTP stopped working even though the security group still allowed them. The logs show the break lasted 42 seconds in this run. Earlier in the day there were similar events during the original setup and the missing subnet-association bug (`AssociateRouteTable`, `DisassociateRouteTable`).

Screenshots:
- `screenshots/07-route-deleted.png`
- `screenshots/08-route-restored.png`

## 4. IAM role denied an action (Nov 17)

The EC2 instance's role (`ec2-s3-upload-role`) is limited to `PutObject` and `GetObject` on one bucket. When I ran `aws s3 ls`, CloudTrail recorded `ListBuckets` with `"errorCode": "AccessDenied"`. The user agent shows the AWS CLI, and the caller was the assumed role.

This is what least privilege looks like in the logs. In real environments, a burst of denied calls from one identity is a common detection signal.

Screenshot: `screenshots/09-listbuckets-denied.png`

## 5. MFA finding

Every console event from my IAM user showed `"mfaAuthenticated": "false"`. The root account had MFA, but the user I used for daily work did not. If that user's password leaked, an attacker would get the same access.

**Action:** enable an MFA device for the IAM user. "Enabled on November 21, 2026, 13:25:00 (UTC+00:00). New sessions show `mfaAuthenticated: true`."

## 6. What CloudTrail can't show me

- **Who read the objects during the 5 minutes the bucket was public.** Object reads are *data events*, which are off by default. I can prove people *could* read the file, not that they did.
- **Network connections.** The scanner only appears in the instance's SSH log.
- **Anything older than 90 days.** Event history is limited to that window. A trail stores events in S3 for longer.
- **ACL changes on objects**, for the same reason as the first point.

## 7. What I learned
- CloudTrail answers "who changed what, when, and from where." It doesn't answer "what is the configuration now" (that's what a CSPM does).
- Two sources often have to be combined (CloudTrail plus the host's own logs) to tell the full story.
- Failed calls are logged too, with an error code.
- Exposure windows can be short and still matter, because scanners find open ports within minutes.
- Check the region: IAM events live in us-east-1, while EC2 and S3 events are in the resource's region.

## 8. Ideas for my mini-CSPM
- Security groups with `0.0.0.0/0` on port 22 or 3389
- S3 buckets with Block Public Access off, or with `Principal: "*"` policies
- IAM users with console access and no MFA
- Policies with `"Action": "*"` or `"Resource": "*"`
- CloudTrail not enabled, not multi-region, or without log file validation

## 9. Next steps
- Create a trail with log file validation, so events are kept in S3 beyond 90 days
- Run Prowler against the account and compare its findings with the ones above
- Build the mini-CSPM in Python (boto3)
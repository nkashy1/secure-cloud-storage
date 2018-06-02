# secure-cloud-storage

Securely store and recover small files using [Google Cloud Storage](https://cloud.google.com/storage/docs/).
Uses [Cloud KMS](https://cloud.google.com/kms/docs/) for encryption.

- - -

## Setup

To use this utility, you have to set up application credentials, either by creating a [GCP service
account](https://cloud.google.com/iam/docs/understanding-service-accounts) with the appropriate
permissions (**recommended**), or by running `gcloud auth application-default` so that the GCS and
KMS requests will be authenticated with your user account.

### Creating a service account

If you would like to use a service account with this utility, and this really is the most secure way
forward, you can [create a service account from the Cloud Console](https://console.cloud.google.com/iam-admin/serviceaccounts).

Make sure that the service account has the following permissions:

+ `Cloud KMS CryptoKey Encrypter/Decrypter` on the KMS project

+ `Storage Object Creator` and `Storage Object Viewer` on the GCS bucket (need not be under the
same project as your KMS keys)

Download credentials for that service account as a JSON file, and you are good to go to the next step.

## Usage

The following samples assume that you have created a service account with the appropriate
permissions and have downloaded a credentials JSON file for that service account. If you prefer to
use your user account to run this utility, omit the `GOOGLE_APPLICATIONS_CREDENTIALS` variable
below.

Store:
```
GOOGLE_APPLICATION_CREDENTIALS=<credentials JSON file> python scs.py \
  --bucket <GCS bucket> \
  --infile <input file path> \
  --outfile <output file path (relative to bucket)> \
  store \
  --key-project <GCP project containing KMS encryption key> \
  --location <KMS location for key> \
  --keyring <KMS keyring> \
  --key <KMS key> \
  --key-version <KMS key version>
```

Retrieve:
```
GOOGLE_APPLICATION_CREDENTIALS=<credentials JSON file> python scs.py \
  --bucket <GCS bucket> \
  --infile <input file path> \
  --outfile <output file path (relative to bucket)> \
  retrieve
```
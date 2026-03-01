# ML Training Data Generation: Automated Harvesting & Labeling

- [ML Training Data Generation: Automated Harvesting \& Labeling](#ml-training-data-generation-automated-harvesting--labeling)
  - [I. Purpose and Scope](#i-purpose-and-scope)
  - [II. Data Sourcing Strategy](#ii-data-sourcing-strategy)
  - [III. Automated Pipeline Execution](#iii-automated-pipeline-execution)
  - [IV. Labeling Rubric](#iv-labeling-rubric)
  - [V. Artifact Storage](#v-artifact-storage)

## I. Purpose and Scope

This aims to define the methodology for generating a robust and effective training set for the decision tree classifier.
Due to a strategically custom feature vector, the system will need a systematic way to generate its own training set.

## II. Data Sourcing Strategy

To ensure a diverse dataset that prevents model overfitting but still realizes relevant features for classification, the 
training process will source targets 

## III. Automated Pipeline Execution

TODO

## IV. Labeling Rubric

TODO

## V. Artifact Storage

To be consistent with the system's auditability requirements, all data generated for the training set will also
be retained. This ensure's traceable decision process during the training process. For each harvested target, the 
pipeline will store:

- SBOM/Vulnerability Scan (produced by [`aquasecurity/trivy`](https://github.com/aquasecurity/trivy))
- SemGrep Scan (produced by [`semgrep/semgrep`](https://github.com/semgrep/semgrep))
- The extracted, normalized feature vector
- Label applied to the feature vector (`ALLOW`, `WARN` ,`BLOCK`)
SECURESENSE AI
VISUAL PHISHING INTELLIGENCE — PRODUCTION MODEL
================================================

Architecture:
ConvNeXt-Tiny

Input:
224 × 224 RGB website screenshot

Classes:
0 = Legitimate
1 = Phishing

Production decision threshold:
0.555

Frozen checkpoint epoch:
16

FINAL TEST PERFORMANCE
----------------------
Accuracy:
0.956124

Balanced Accuracy:
0.814254

Phishing Precision:
0.783784

Phishing Recall:
0.644444

Phishing F1:
0.707317

MCC:
0.687675

ROC-AUC:
0.951062

PR-AUC:
0.802545

Specificity:
0.984064

MODEL INTEGRITY
---------------
SHA-256:
16f93db0255b5743afa6dff6747b98bf35b2399ff455dedd77f30e9f2d476ea1

IMPORTANT
---------
This model and its threshold were frozen before final test
evaluation.

The final test set must not be used to retune this model,
checkpoint or threshold.
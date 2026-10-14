# Future OIDC deployment reference — disabled

The interview uses automated CI and manual CD through `cdk-sso`.
`oidc-deployment.yml.disabled` preserves the earlier implementation outside the
Actions workflow directory. Its deployment job also has `if: ${{ false }}`.
No GitHub environment/variable or Run workflow action can enable it in current CI.

This is historical design code, not a runnable deployment recipe. The app now uses
standard bootstrap roles and creates its runtime boundary inside ClaimsTeamStack.
The archived workflow/Platform IAM generator used custom execution roles and a
`claims/` asset prefix. Their permissions and assembly assumptions require review
before restoration; creating an owned managed policy needs appropriate permissions.

Keep the change-set and GitHub readiness helper tests as future safety examples.
Future work needs explicit approval, reviewed OIDC trust and scoped AWS permissions,
protected review/deployment settings, tested artifact handoff, and a live proof.
Do not recreate the user's deleted role or provision old access resources for the
current manual demonstration. See Platform DEPLOYMENT.md for the active workflow.

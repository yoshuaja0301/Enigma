import unittest

from enigma.authorization.validator import AuthorizationValidator, BlockStage
from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target


def make_assessment(status=AuthorizationStatus.AUTHORIZED, hosts=("authorized-target.example",)):
    return Assessment(
        assessment_id="ASM-TEST",
        target=Target("https://authorized-target.example/"),
        authorization=Authorization(status=status),
        scope=Scope(allowed_hosts=list(hosts), excluded_paths=["/logout"]),
        profile=AssessmentProfile.SAFE_VERIFICATION,
    )


class AuthorizationValidatorTests(unittest.TestCase):
    def test_authorized_in_scope_get(self):
        validator = AuthorizationValidator(make_assessment())
        result = validator.authorize("https://authorized-target.example/search", "GET")
        self.assertTrue(result.allowed)
        self.assertEqual(result.stage, BlockStage.NONE)

    def test_blocks_when_unauthorized(self):
        validator = AuthorizationValidator(make_assessment(status=AuthorizationStatus.UNKNOWN))
        result = validator.authorize("https://authorized-target.example/search", "GET")
        self.assertFalse(result.allowed)
        self.assertEqual(result.stage, BlockStage.AUTHORIZATION)

    def test_blocks_out_of_scope(self):
        validator = AuthorizationValidator(make_assessment())
        result = validator.authorize("https://evil.example/", "GET")
        self.assertFalse(result.allowed)
        self.assertEqual(result.stage, BlockStage.SCOPE)

    def test_blocks_state_changing_method(self):
        validator = AuthorizationValidator(make_assessment())
        result = validator.authorize("https://authorized-target.example/search", "DELETE")
        self.assertFalse(result.allowed)
        self.assertEqual(result.stage, BlockStage.POLICY)

    def test_blocks_excluded_path(self):
        validator = AuthorizationValidator(make_assessment())
        result = validator.authorize("https://authorized-target.example/logout", "GET")
        self.assertFalse(result.allowed)
        self.assertEqual(result.stage, BlockStage.SCOPE)


if __name__ == "__main__":
    unittest.main()

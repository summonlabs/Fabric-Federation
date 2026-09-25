// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Model tests: scopes, capabilities, constitutions, identity binding and
// policy validation.
#include "fixture.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;
using namespace ffed_test;

FFED_TEST(scope, name_validation_is_strict) {
  const ScopeCatalog& catalog = ScopeCatalog::builtin();
  FFED_CHECK(ScopeId::parse("federation.route.advertise").has_value());
  FFED_CHECK(ScopeId::parse("domain.member.control").has_value());
  FFED_CHECK(ScopeId::parse("federation.*").has_value());
  FFED_CHECK(ScopeId::parse("*").has_value());
  FFED_CHECK(!ScopeId::parse("").has_value());
  FFED_CHECK(!ScopeId::parse("Federation.Route").has_value());
  FFED_CHECK(!ScopeId::parse("federation..route").has_value());
  FFED_CHECK(!ScopeId::parse(".federation").has_value());
  FFED_CHECK(!ScopeId::parse("federation.").has_value());
  FFED_CHECK(!ScopeId::parse("federation route").has_value());
  FFED_CHECK(!ScopeId::parse("federation.*.extra").has_value());
  FFED_CHECK(!ScopeId::parse(std::string(kMaxIdentifierLength + 1, 'a')).has_value());

  bool known = false;
  FFED_CHECK_EQ(catalog.classify(ScopeId::parse("federation.route.advertise").value(), known),
                ScopeClass::GlobalMutation);
  FFED_CHECK(known);
  FFED_CHECK_EQ(catalog.classify(ScopeId::parse("federation.route.observe").value(), known),
                ScopeClass::Federation);
  FFED_CHECK(known);
  FFED_CHECK_EQ(catalog.classify(ScopeId::parse("domain.anything").value(), known),
                ScopeClass::Local);
  FFED_CHECK(known);
  const ScopeClass unknown_class =
      catalog.classify(ScopeId::parse("federation.not.invented").value(), known);
  FFED_CHECK(!known);
  FFED_CHECK_EQ(unknown_class, ScopeClass::Federation);
}

FFED_TEST(scope, wildcard_coverage_is_prefix_based) {
  const ScopeId pattern = ScopeId::parse("federation.route.*").value();
  FFED_CHECK(pattern.covers(ScopeId::parse("federation.route.advertise").value()));
  FFED_CHECK(pattern.covers(ScopeId::parse("federation.route.a.b").value()));
  FFED_CHECK(!pattern.covers(ScopeId::parse("federation.routes").value()));
  FFED_CHECK(!pattern.covers(ScopeId::parse("federation.other").value()));
  FFED_CHECK(ScopeId::parse("*").value().covers(ScopeId::parse("anything.at.all").value()));

  std::vector<ScopeGrant> grants;
  grants.push_back(ScopeGrant{ScopeId::parse("federation.route.*").value(), AuthorityVerb::Mutate});
  FFED_CHECK(grants_cover(grants, ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                             AuthorityVerb::Mutate}));
  FFED_CHECK(!grants_cover(grants, ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                              AuthorityVerb::Observe}));

  const std::vector<ScopeGrant> concrete = {
      ScopeGrant{ScopeId::parse("federation.route.advertise").value(), AuthorityVerb::Mutate},
      ScopeGrant{ScopeId::parse("federation.health.report").value(), AuthorityVerb::Write}};
  const std::vector<ScopeGrant> intersection = intersect_grants(concrete, grants);
  FFED_CHECK_EQ(intersection.size(), std::size_t{1});
  FFED_CHECK_EQ(intersection.front().scope.str(), std::string("federation.route.advertise"));
}

FFED_TEST(capability, compatibility_matrix) {
  const auto protocol = CapabilityId::parse("federation.protocol.v1").value();
  const auto invented = CapabilityId::parse("federation.not.modelled").value();

  CapabilityRequirement requirement;
  requirement.capability = protocol;
  requirement.min_version = 1;
  requirement.max_version = 1;
  requirement.mandatory = true;

  CapabilityStatement statement;
  statement.capability = protocol;
  statement.version = 1;
  statement.evidence = EvidenceState::Known;
  statement.evidence_digest = Digest::of("evidence");

  FFED_CHECK_EQ(evaluate_compatibility({requirement}, {statement}).state,
                CompatibilityState::Satisfied);
  FFED_CHECK_EQ(evaluate_compatibility({requirement}, {}).state, CompatibilityState::Unknown);
  FFED_CHECK_EQ(evaluate_compatibility({requirement}, {statement}).summary.empty(), false);

  CapabilityStatement asserted = statement;
  asserted.evidence = EvidenceState::Unknown;
  FFED_CHECK_EQ(evaluate_compatibility({requirement}, {asserted}).state,
                CompatibilityState::Unknown);

  CapabilityStatement wrong_version = statement;
  wrong_version.version = 3;
  FFED_CHECK_EQ(evaluate_compatibility({requirement}, {wrong_version}).state,
                CompatibilityState::Incompatible);

  CapabilityStatement duplicate = statement;
  duplicate.version = 2;
  FFED_CHECK_EQ(evaluate_compatibility({requirement}, {statement, duplicate}).state,
                CompatibilityState::Conflicting);

  CapabilityRequirement unknown = requirement;
  unknown.capability = invented;
  FFED_CHECK_EQ(evaluate_compatibility({unknown}, {}).state, CompatibilityState::Unsupported);

  CapabilityRequirement optional = requirement;
  optional.mandatory = false;
  FFED_CHECK_EQ(evaluate_compatibility({optional}, {}).state, CompatibilityState::Unknown);
  FFED_CHECK_EQ(evaluate_compatibility({}, {}).state, CompatibilityState::Satisfied);
}

FFED_TEST(constitution, validation_rejects_self_transfer_and_unknown_scopes) {
  const ScopeCatalog& catalog = ScopeCatalog::builtin();
  const FixtureMember member = make_member("constitution", 1);
  FFED_CHECK(validate_constitution(member.constitution, catalog).ok());

  MemberConstitution overlapping = member.constitution;
  overlapping.retained.push_back(
      ScopeGrant{ScopeId::parse("federation.route.advertise").value(), AuthorityVerb::Mutate});
  canonicalize_grants(overlapping.retained);
  FFED_CHECK_EQ(validate_constitution(overlapping, catalog).code(), ErrorCode::InvalidArgument);

  MemberConstitution domain_delegation = member.constitution;
  DelegationTerms terms;
  terms.grant.scope = ScopeId::parse("domain.member.control").value();
  terms.grant.verb = AuthorityVerb::Administer;
  domain_delegation.delegated.push_back(terms);
  canonicalize_terms(domain_delegation.delegated);
  FFED_CHECK_EQ(validate_constitution(domain_delegation, catalog).code(),
                ErrorCode::InvalidArgument);

  MemberConstitution unknown = member.constitution;
  DelegationTerms invented;
  invented.grant.scope = ScopeId::parse("federation.invented.scope").value();
  invented.grant.verb = AuthorityVerb::Mutate;
  unknown.delegated.push_back(invented);
  canonicalize_terms(unknown.delegated);
  FFED_CHECK_EQ(validate_constitution(unknown, catalog).code(), ErrorCode::InvalidArgument);

  MemberConstitution everything = member.constitution;
  DelegationTerms all;
  all.grant.scope = ScopeId::parse("*").value();
  all.grant.verb = AuthorityVerb::Administer;
  everything.delegated.push_back(all);
  canonicalize_terms(everything.delegated);
  FFED_CHECK_EQ(validate_constitution(everything, catalog).code(), ErrorCode::InvalidArgument);

  MemberConstitution no_identity = member.constitution;
  no_identity.member = MemberId();
  FFED_CHECK_EQ(validate_constitution(no_identity, catalog).code(), ErrorCode::InvalidArgument);
}

FFED_TEST(constitution, digest_binds_every_field) {
  const FixtureMember base = make_member("digest-binding", 1);
  const Digest baseline = base.constitution.digest();
  FFED_CHECK(!baseline.is_zero());

  MemberConstitution generation = base.constitution;
  generation.generation = Generation(2);
  FFED_CHECK(generation.digest() != baseline);

  MemberConstitution retained = base.constitution;
  retained.retained.clear();
  FFED_CHECK(retained.digest() != baseline);

  MemberConstitution delegated = base.constitution;
  delegated.delegated.front().mode = delegated.delegated.front().mode == DelegationMode::Shared
                                         ? DelegationMode::Exclusive
                                         : DelegationMode::Shared;
  FFED_CHECK(delegated.digest() != baseline);

  MemberConstitution description = base.constitution;
  description.description = "different";
  FFED_CHECK(description.digest() != baseline);

  MemberConstitution capability = base.constitution;
  capability.capabilities.front().version = 2;
  FFED_CHECK(capability.digest() != baseline);

  MemberConstitution reordered = base.constitution;
  reordered.capabilities.clear();
  reordered.retained.clear();
  reordered.delegated.clear();
  reordered.canonicalize();
  FFED_CHECK(reordered.digest() != baseline);
}

FFED_TEST(identity, comparison_reports_the_first_difference) {
  const FixtureMember member = make_member("identity", 1);
  MemberIdentity identity = member.identity();
  FFED_CHECK_EQ(compare_identities(identity, identity), IdentityMismatch::None);

  MemberIdentity other_generation = identity;
  other_generation.generation = Generation(2);
  FFED_CHECK_EQ(compare_identities(identity, other_generation), IdentityMismatch::Generation);

  MemberIdentity other_incarnation = identity;
  other_incarnation.incarnation = Incarnation(2);
  FFED_CHECK_EQ(compare_identities(identity, other_incarnation), IdentityMismatch::Incarnation);

  MemberIdentity other_digest = identity;
  other_digest.constitution = Digest::of("changed");
  FFED_CHECK_EQ(compare_identities(identity, other_digest), IdentityMismatch::Constitution);

  MemberIdentity other_member = identity;
  other_member.member = MemberId::derive("elsewhere", 1);
  FFED_CHECK_EQ(compare_identities(identity, other_member), IdentityMismatch::Member);

  FFED_CHECK_EQ(MembershipSlot::make(member.member, Lineage(0)).lineage_id,
                MembershipSlot::make(member.member, Lineage(0)).lineage_id);
  FFED_CHECK(MembershipSlot::make(member.member, Lineage(0)).lineage_id !=
             MembershipSlot::make(member.member, Lineage(1)).lineage_id);
}

FFED_TEST(policy, defaults_are_conservative_and_validation_is_strict) {
  const FederationPolicy policy = default_policy();
  FFED_CHECK(validate_policy(policy).ok());
  FFED_CHECK_EQ(policy.required_distinct_parties(), std::size_t{2});
  FFED_CHECK_EQ(policy.required_endorsements(), std::size_t{0});
  FFED_CHECK(policy.lease_required(
      ScopeGrant{ScopeId::parse("federation.route.advertise").value(), AuthorityVerb::Mutate}));
  FFED_CHECK(!policy.lease_required(
      ScopeGrant{ScopeId::parse("federation.route.observe").value(), AuthorityVerb::Observe}));
  FFED_CHECK(policy.reconsent_on_generation_change());
  FFED_CHECK(policy.suspend_global_mutation_on_partition());
  FFED_CHECK(policy.suspend_global_mutation_while_reconciling());
  FFED_CHECK(policy.require_reattestation_after_partition());
  FFED_CHECK(policy.precedence_for(ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                              AuthorityVerb::Mutate}) == nullptr);
  FFED_CHECK_EQ(policy.digest(), default_policy().digest());

  FederationPolicy duplicated = policy;
  duplicated.rules.push_back(duplicated.rules.front());
  FFED_CHECK_EQ(validate_policy(duplicated).code(), ErrorCode::Conflict);

  FederationPolicy weak = policy;
  for (PolicyRule& rule : weak.rules) {
    if (rule.kind == PolicyRuleKind::RequireDistinctParties) {
      rule.value = 1;
    }
  }
  FFED_CHECK_EQ(validate_policy(weak).code(), ErrorCode::InvalidArgument);

  FederationPolicy precedence = policy;
  PolicyRule rule;
  rule.id = RuleId::parse("test.precedence").value();
  rule.kind = PolicyRuleKind::PrecedenceForGrant;
  rule.scope = ScopeId::parse("federation.route.advertise").value();
  rule.members = {MemberId::derive("a", 1), MemberId::derive("a", 1)};
  precedence.rules.push_back(rule);
  FFED_CHECK_EQ(validate_policy(precedence).code(), ErrorCode::Conflict);
}

FFED_TEST(evidence, artefact_validation_is_structural) {
  const FederationFixture fixture;
  const FixtureMember candidate = make_member("evidence", 1);
  const Artifact artifact = proposal(fixture.federation, candidate, fixture.founder);
  const ScopeCatalog& catalog = ScopeCatalog::builtin();
  FFED_CHECK(artifact.validate(catalog).ok());
  FFED_CHECK(artifact.verify_digest().ok());

  Artifact tampered = artifact;
  tampered.body.lineage = Lineage(9);
  FFED_CHECK_EQ(tampered.verify_digest().code(), ErrorCode::ChecksumMismatch);
  FFED_CHECK_EQ(tampered.validate(catalog).code(), ErrorCode::ChecksumMismatch);

  Artifact foreign = artifact;
  foreign.envelope.federation = FederationId::derive("elsewhere", 1);
  FFED_CHECK(foreign.validate(catalog).ok());  // structurally valid, wrong federation

  Artifact no_subject = artifact;
  no_subject.envelope.subject = MemberId();
  no_subject.envelope.body_digest = no_subject.body.digest();
  FFED_CHECK_EQ(no_subject.validate(catalog).code(), ErrorCode::InvalidArgument);

  // A member-issued artefact must name the member that issued it.
  Artifact anonymous = artifact;
  anonymous.envelope.issuer.member = MemberId();
  anonymous.envelope.body_digest = anonymous.body.digest();
  FFED_CHECK_EQ(anonymous.validate(catalog).code(), ErrorCode::InvalidArgument);
}

FFED_TEST(evidence, encode_decode_round_trip) {
  const FederationFixture fixture;
  const FixtureMember candidate = make_member("roundtrip", 1);
  for (const Artifact& artifact :
       {proposal(fixture.federation, candidate, fixture.founder),
        acceptance(fixture.federation, candidate),
        endorsement(fixture.federation, candidate, fixture.founder),
        withdrawal(fixture.federation, candidate,
                   {ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                               AuthorityVerb::Mutate}})}) {
    Writer writer;
    FFED_REQUIRE(artifact.encode(writer).ok());
    Reader reader(writer.span());
    auto decoded = Artifact::decode(reader);
    FFED_REQUIRE(decoded.has_value());
    FFED_CHECK(reader.expect_end().ok());
    FFED_CHECK_EQ(decoded.value().digest(), artifact.digest());
    FFED_CHECK(decoded.value().validate(ScopeCatalog::builtin()).ok());
  }
}

FFED_TEST_MAIN()

from detection.behavior.scoring import behavior_score


def test_behavior_score_ratio_scale_and_cap():
    assert behavior_score(10, 10) == 30
    assert behavior_score(20, 10) == 60
    assert behavior_score(30, 10) == 90
    assert behavior_score(40, 10) == 100


def test_behavior_score_uses_minimum_reference():
    assert behavior_score(1, 0, minimum_reference=2) == 15

from fixture_pkg import answer


def test_answer() -> None:
    assert answer() == 41

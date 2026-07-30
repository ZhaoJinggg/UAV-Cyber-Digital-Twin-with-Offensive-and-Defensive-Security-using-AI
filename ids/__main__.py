"""python -m ids  → train | score | cnn"""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in {"score", "replay"}:
        sys.argv = [sys.argv[0], *sys.argv[2:]]
        from ids.live_scorer import main as score_main

        return score_main()
    if len(sys.argv) > 1 and sys.argv[1] in {"cnn", "cnn_train", "train_cnn"}:
        sys.argv = [sys.argv[0], *sys.argv[2:]]
        from ids.cnn_train import main as cnn_main

        return cnn_main()
    from ids.train import main as train_main

    return train_main()


if __name__ == "__main__":
    raise SystemExit(main())

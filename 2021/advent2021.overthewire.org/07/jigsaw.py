import os
import logging
import numpy as np
import sys

from piece_finder import Piece
from edge_finder import SideOrientation


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
log.addHandler(handler)


class Jigsaw:

    def __init__(self, folder):
        self.pieces = self._get_pieces(folder)

    def _get_pieces(self, folder):
        pieces = []
        count = 0
        for filename in os.listdir(folder):
            if filename.endswith(".png"):
                img_path = os.path.join(folder, filename)
                log.info(img_path)
                piece = Piece(img_path)
                if piece.is_corner:
                    piece.save_mask(f'output/{filename}')
                pieces.append(piece)

        return pieces

    def check_sides_match(self, left_piece: Piece, right_piece: Piece) -> bool:

        rhs = left_piece.sides.right
        lhs = right_piece.sides.left

        # Make sure the sides are compatible
        if rhs.orientation == lhs.orientation == SideOrientation.HEAD \
                or rhs.orientation == lhs.orientation == SideOrientation.HOLE \
                or rhs.orientation ==  SideOrientation.STRAIGHT \
                or lhs.orientation == SideOrientation.STRAIGHT:
            return False

        merged = []
        for x, y in zip(lhs.coords, rhs.coords):
            merged.append(x, y)
            dist.append(x - y)
        print("Subtraction:")
        print(f"{dist}\n\n\n")

        euclidean_norm = np.linalg.norm(lhs.coords - rhs.coords)
        print(f"euclidean_norm:")
        print(f"{euclidean_norm}\n\n\n")

        stddev = np.std(dist)
        print("std dev:")
        print(f"{stddev}\n\n\n")


        # What do we do about the y axis here? Not sure if pieces will always
        # have matching corners

        # Apply the distance to the rest of the sides

        # Check the average abs() distance between each piece on the x axis

        # If it's above a threshold add it to the candidates list
        return True


if __name__ == '__main__':
    folder = "jigsaw_pieces"
    jigsaw = Jigsaw(folder)
    corners = [p for p in jigsaw.pieces if p.is_corner]
    straights = [p for p in jigsaw.pieces if p.is_straight]
    print("\n\n\nStraights:")
    print([s.filename for s in straights])


import cv2
import logging
import os
import numpy as np
import sys

from corner_finder import get_corners
from edge_finder import get_sides, SideOrientation


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
log.addHandler(handler)

class Piece:
    def __init__(self, image_path):
        self.image_path = image_path
        self.filename = os.path.basename(image_path)
        self.image = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        self._set_piece_variables()

    def save_mask(self, filename):

        # Create a blank canvas the same size as the image
        shape = (self.image.shape[0], self.image.shape[1], 3)
        mask = np.ones(shape, dtype="uint8") * 255

        # Mark out the sides as black
        for side in self.sides.get_sides():
            shape = Piece._swap_xy(side.coords)
            if side.orientation == SideOrientation.STRAIGHT:
                mask[tuple(zip(*shape))] = [0, 255, 0]
            elif side.orientation == SideOrientation.HEAD:
                mask[tuple(zip(*shape))] = [255, 0, 0]
            elif side.orientation == SideOrientation.HOLE:
                mask[tuple(zip(*shape))] = [0, 0, 255]
            else:
                raise ValueError(f"Invalid SideOrientation: {side.orientation}")

        # Mark the corners as green
        mask[self.corners.coords[:,1], self.corners.coords[:,0]] = [0,0,0]
        cv2.imwrite(filename, mask)

    def _set_piece_variables(self):
        self.corners = get_corners(self.image)
        self.sides = get_sides(self.image, self.corners)
        self.is_corner = self._get_straight_sides_count() == 2
        self.is_straight = self._get_straight_sides_count() > 0

    def _get_straight_sides_count(self):
        straight_sides = [s for s in self.sides.get_sides()
                          if s.orientation == SideOrientation.STRAIGHT]
        return len(straight_sides)

    @staticmethod
    def _swap_xy(array):
        """ Swap the x/y values of a 2D array, as cv2 and numpy index differently """
        array = np.copy(array)
        tmp = np.copy(array[:,1])
        array[:,1] = array[:,0]
        array[:,0] = tmp
        return array

if __name__ == '__main__':
    folder = "jigsaw_pieces"
    pieces = []
    for filename in os.listdir(folder):
        if filename.endswith(".png"):
            img_path = os.path.join(folder, filename)
            log.info(img_path)
            piece = Piece(img_path)
            if piece.is_corner:
                piece.save_mask(f'output/{filename}')
            pieces.append(piece)


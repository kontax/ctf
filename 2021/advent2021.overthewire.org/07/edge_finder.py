import cv2
import logging
import numpy as np
import os
import sys

from corner_finder import Corner, get_corners
from enum import Enum


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
log.addHandler(handler)


class SidePosition(Enum):
    LEFT = 0
    TOP = 1
    BOTTOM = 2
    RIGHT = 3


class SideOrientation(Enum):
    HEAD = 0
    HOLE = 1
    STRAIGHT = 2


class Side:
    def __init__(self, position: SidePosition, corners: list[Corner], coords):
        self.position = position
        self.corners = corners
        self.coords = np.array(coords)
        self.orientation = self._get_orientation()


    def _get_orientation(self) -> SideOrientation:
        """
        Get the orientation for the side whether it's a head, hole or straight 

        This gets the equation of the line bewteen the two corner pieces of
        the side and calculates the distance from that line to the barycentre
        of all the points of the side. This allows us to see whether the line
        trends to the left or the right of the corners.
        """

        bc = Side._compute_barycentre(self.coords)
        corner_str = [f"{c.position}: {c.__str__()}" for c in self.corners]

        # Functions to calculate whether a point is above a line or not
        # y = (c-ax)/b | x = (c-by)/a
        line = lambda p, c0, c1, c2: (c2-c0*p)/c1
        line_dist = lambda p0, p1, c0, c1, c2: p1 - line(p0, c0, c1, c2)

        # Get the coefficients of the line
        coeff = _get_coefficients(self.corners[0], self.corners[1])

        if self.position in [SidePosition.LEFT, SidePosition.RIGHT]:
            # We want the value of x for left and right sides
            dist = line_dist(bc[1], bc[0], coeff[1], coeff[0], coeff[2])
        else:
            # We want the value of y for top and bottom sides
            dist = line_dist(bc[0], bc[1], coeff[0], coeff[1], coeff[2])

        # If the distance from the corner line is 0 then it's a straight piece
        if dist == 0:
            return SideOrientation.STRAIGHT

        # The distance is the distance from the line on a particular axis,
        # so we need to swap the sign for left and top sides
        if self.position in [SidePosition.LEFT, SidePosition.TOP]:
            dist = -dist

        return SideOrientation.HOLE if dist < 0 else SideOrientation.HEAD

    @staticmethod
    def _compute_barycentre(coords):
        """ Computes the barycentre of a list of points. This is the avg
        location of all the points in the side so we can compare it to
        the corner line and see what side the point is on """
        return [int(np.round(c.mean())) for c in coords.transpose()]

    def __str__(self):
        return f"{self.position} side"


class Sides:
    def __init__(self, sides: list[Side]):
        self._sides = sides
        self.left = next(filter(lambda x: x.position == SidePosition.LEFT, sides))
        self.top = next(filter(lambda x: x.position == SidePosition.TOP, sides))
        self.right = next(filter(lambda x: x.position == SidePosition.RIGHT, sides))
        self.bottom = next(filter(lambda x: x.position == SidePosition.BOTTOM, sides))

    def get_sides(self):
        return self._sides


def get_sides_by_path(img_path):
    image = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
    corners = get_corners(image)
    log.debug(f"Corners: {corners}")
    sides = get_sides(image, corners)
    log.debug(f"Sides: {sides}")
    return sides


def get_sides(image, corners):

    edges = _get_canny_edges(image)

    sides = {
        'left': [],
        'top': [],
        'right': [],
        'bottom': []
    }

    tl = corners.top_left
    tr = corners.top_right
    bl = corners.bottom_left
    br = corners.bottom_right

    # Get the coefficients for the line equation y = ax + b for the lines
    # going top-left to bottom-right and bottom-left to top-right

    tl_br_coeff = _get_coefficients(tl, br)
    bl_tr_coeff = _get_coefficients(bl, tr)


    # Functions to calculate whether a point is above a line or not
    line = lambda px, coeff: (coeff[2]-coeff[0]*px) / coeff[1]
    line_dist = lambda pt, coeff: pt[1] - line(pt[0], coeff)

    for p in edges:
        if line_dist(p, tl_br_coeff) <= 0 and line_dist(p, bl_tr_coeff) > 0:
            sides['right'].append(list(p))
        elif line_dist(p, tl_br_coeff) > 0 and line_dist(p, bl_tr_coeff) > 0:
            sides['bottom'].append(list(p))
        elif line_dist(p, tl_br_coeff) > 0 and line_dist(p, bl_tr_coeff) <= 0:
            sides['left'].append(list(p))
        elif line_dist(p, tl_br_coeff) <= 0 and line_dist(p, bl_tr_coeff) <= 0:
            sides['top'].append(list(p))
        else:
            log.error(f"{p} cannot be found between {corners}")
            raise ValueError("Cannot find coefficent quadrant")

    return Sides([
            Side(SidePosition.RIGHT, [corners.top_right, corners.bottom_right], sides['right']),
            Side(SidePosition.BOTTOM, [corners.bottom_left, corners.bottom_right], sides['bottom']),
            Side(SidePosition.LEFT, [corners.top_left, corners.bottom_left], sides['left']),
            Side(SidePosition.TOP, [corners.top_left, corners.top_right], sides['top']),
        ])



def _get_canny_edges(image):

    # read/load an image
    img_trns = np.copy(image)
    for i in range(3):
        img_trns[:,:,i] = np.where(image[:,:,3] > 0, 255, 0)

    # Add a border
    image_with_border = cv2.copyMakeBorder(img_trns, 10, 10, 10, 10, cv2.BORDER_CONSTANT, value=[0,0,0,0])

    # detection of the edges
    img_edge = cv2.Canny(image_with_border,100,200)

    # Find the pixel values and remove the border
    img_idx = np.argwhere(img_edge == 255)-10

    # Swap the x/y values to be in line with cv2
    img_idx = _swap_xy(img_idx)

    # Ensure points right at the edge aren't outside the image boundaries
    w, h, _ = image.shape
    img_idx[:,0] = np.clip(img_idx[:,0], a_min=0, a_max=h-1)
    img_idx[:,1] = np.clip(img_idx[:,1], a_min=0, a_max=w-1)

    return img_idx


def _print_mask(image, shape, filename):
    mask = np.ones(image.shape[:2], dtype="uint8") * 255
    shape = _swap_xy(shape)
    mask[tuple(zip(*shape))] = 0
    cv2.imwrite(filename, mask)


def _get_coefficients(p1, p2):
    """ Get the coefficients for the line passing between p1 and p2 """
    a = p2.x - p1.x
    b = p1.y - p2.y
    c = a*p1.y + b*p1.x
    return a, b, c


def _swap_xy(array):
    """ Swap the x/y values of a 2D array, as cv2 and numpy index differently """
    array = np.copy(array)
    tmp = np.copy(array[:,1])
    array[:,1] = array[:,0]
    array[:,0] = tmp
    return array


if __name__ == '__main__':
    #img_path = "jigsaw_pieces/0058a0eb229f3b028da843249197e2f4d9758e2aa65221d093a76355ded4ac8f.png"
    folder = "jigsaw_pieces"
    for filename in os.listdir(folder):
        if filename.endswith(".png"):
            img_path = os.path.join(folder, filename)
            log.info(img_path)
            image = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
            sides = get_sides_by_path(img_path)
            #for x in ['right', 'left', 'top', 'bottom']:
                #_print_mask(image, sides[x], f'test-{x}.png')

import cv2
import numpy as np
import os

from enum import Enum

BLOCK_SIZE = 5  # Neighbourhood size (cornerEigenValsAndVecs)
K_SIZE = 7      # Aperture parameter for the Sobel operator
K_MIN = 0.02    # Minimum Harris detector free parameter
K_MAX = 0.17    # Maximum Harris detector free parameter
BOUNDS = 0.25   # Pct of image to limit corner detection to


class CornerPosition(Enum):
    TOP_LEFT = 0
    BOTTOM_LEFT = 1
    TOP_RIGHT = 2
    BOTTOM_RIGHT = 3


class Corner:
    def __init__(self, position: CornerPosition, coords):
        self.position = position
        self.coords = coords
        self.x = coords[1]
        self.y = coords[0]

    def __str__(self):
        return str(self.coords)


class Corners:
    def __init__(self, corners: list[Corner]):
        self._corners = corners
        self.coords = np.array([c.coords for c in self._corners])
        self.top_left = next(filter(lambda x: x.position == CornerPosition.TOP_LEFT, corners))
        self.bottom_left = next(filter(lambda x: x.position == CornerPosition.BOTTOM_LEFT, corners))
        self.top_right = next(filter(lambda x: x.position == CornerPosition.TOP_RIGHT, corners))
        self.bottom_right = next(filter(lambda x: x.position == CornerPosition.BOTTOM_RIGHT, corners))

    def __str__(self):
        return str([f"{c.position}: {c.__str__()}" for c in self._corners])


def get_corners(img, save_output=False):
    """ Given the path to an `image`, try find the corners of the pieces """

    # If we don't find the correct corners at first pass, keep reducing the
    # K value until we do, or error out
    k = K_MAX
    while True:

        # Get the corner estimates and remove those out of bounds
        harris_corners = _get_harris_corners(img, k)
        harris_corners = _remove_corners_out_of_bounds(img, harris_corners)

        # Ensure we have 4 corners, one in each quadrant
        if len(harris_corners) == 4 \
                and _check_corner_quadrants(img, harris_corners):

            # If so we're done
            break

        if k <= K_MIN:
            raise AssertionError(f"Corners cannot be found: {len(harris_corners)}")

        # Otherwise keep reducing K until we find something
        k -= 0.01

    w, h, _ = img.shape

    # Ensure points right at the edge aren't outside the image boundaries
    harris_corners[:,0] = np.clip(harris_corners[:,0], a_min=0, a_max=h-1)
    harris_corners[:,1] = np.clip(harris_corners[:,1], a_min=0, a_max=w-1)

    if save_output:
        # Mark the corners as green and save the image
        img[harris_corners[:,1], harris_corners[:,0]] = [0,255,0,255]
        cv2.imwrite('test.png',img)

    labelled_corners = _get_labelled_corners(harris_corners)

    return labelled_corners


def _get_harris_corners(img, k):

    # Just make the image match the transparency value
    img_trns = np.copy(img)
    for i in range(3):
        img_trns[:,:,i] = np.where(img[:,:,3] > 0, 255, 0)

    image_with_border = cv2.copyMakeBorder(img_trns, 10, 10, 10, 10, cv2.BORDER_CONSTANT, value=[0,0,0,0])
    gray = cv2.cvtColor(image_with_border,cv2.COLOR_BGR2GRAY)

    # find Harris corners
    gray = np.float32(gray)
    dst = cv2.cornerHarris(gray, BLOCK_SIZE, K_SIZE, k)
    dst = cv2.dilate(dst,None)
    dst = cv2.threshold(dst,0.01*dst.max(),255,0)[1]
    dst = np.uint8(dst)

    # find centroids
    centroids = cv2.connectedComponentsWithStats(dst)[3]

    # define the criteria to stop. We stop it after a specified number of iterations
    # or a certain accuracy is achieved, whichever occurs first.
    criteria = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 100, 0.001)

    # Refine the corners using cv2.cornerSubPix()
    corners = cv2.cornerSubPix(gray,np.float32(centroids),(5,5),(-1,-1),criteria)

    # To display, first convert the centroids and corners to integer
    corners = np.int0(np.round(corners))-10

    return corners


def _remove_corners_out_of_bounds(img, corners):

    # Remove anything that isn't in the `BOUNDS` edge limit of the image
    w, h, _ = img.shape
    w_boundary = w*BOUNDS
    h_boundary = h*BOUNDS
    width_map = (corners[:,1] < w_boundary) | (corners[:,1] > w-w_boundary)
    height_map = (corners[:,0] < h_boundary) | (corners[:,0] > h-h_boundary)
    out_of_bounds = width_map & height_map
    return corners[out_of_bounds]


def _check_corner_quadrants(img, corners):

    # Ensure that only one corner is in each quadrant of the image
    w, h, _ = img.shape
    w_boundary = w*BOUNDS
    h_boundary = h*BOUNDS
    retval = sum(np.int0((corners[:,0] < h_boundary) & (corners[:,1] < w_boundary))) == 1 \
         & sum(np.int0((corners[:,0] > h-h_boundary) & (corners[:,1] < w_boundary))) == 1 \
         & sum(np.int0((corners[:,0] < h_boundary) & (corners[:,1] > w-w_boundary))) == 1 \
         & sum(np.int0((corners[:,0] > h_boundary) & (corners[:,1] > w-w_boundary))) == 1
    return retval


def _get_labelled_corners(corners):
    corners[:,1], corners[:,0] = _sort_xy(corners[:,1],corners[:,0])
    return Corners([
        Corner(CornerPosition.BOTTOM_RIGHT, list(corners[0])),
        Corner(CornerPosition.TOP_RIGHT, list(corners[1])),
        Corner(CornerPosition.TOP_LEFT, list(corners[2])),
        Corner(CornerPosition.BOTTOM_LEFT, list(corners[3])),
    ])

def _sort_xy(x, y):

    x0 = np.mean(x)
    y0 = np.mean(y)

    r = np.sqrt((x-x0)**2 + (y-y0)**2)

    angles = np.where((y-y0) > 0, np.arccos((x-x0)/r), 2*np.pi-np.arccos((x-x0)/r))

    mask = np.argsort(angles)

    x_sorted = x[mask]
    y_sorted = y[mask]

    return x_sorted, y_sorted


if __name__ == '__main__':
    folder = "jigsaw_pieces"
    for filename in os.listdir(folder):
        if filename.endswith(".png"):
            full_path = os.path.join(folder, filename)
            print(full_path)
            img = cv2.imread(full_path, cv2.IMREAD_UNCHANGED)
            get_corners(img)


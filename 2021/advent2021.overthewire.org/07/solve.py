import logging
import os
import sys

from PIL import Image


TRANSPARENT_ROW_PCT = 0.4   # Percenatage of the row to be transparent to count as a side
PIX_DIFF_THRESHOLD = 0.035  # Threshold pct difference to say pixels are similar


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
log.addHandler(handler)


class JigsawPiece:
    def __init__(self, path):
        self.path = path
        self.img = Image.open(path)
        self.filename = os.path.basename(path)
        self.width, self.height = self.img.size
        self.pixels = self.get_pixels()
        self.straight_sides = self.get_straight_sides()
        self.is_corner = len(self.straight_sides) == 2
        self.is_straight = len(self.straight_sides) >= 1


    def rotate(self):
        self.img = self.img.transpose(Image.Transverse)
        self.width, self.height = self.img.size
        self.pixels = self.get_pixels()
        self.straight_sides = self.get_straight_sides()
        self.is_corner = len(self.straight_sides) == 2
        self.is_straight = len(self.straight_sides) >= 1


    def get_pixels(self):
        pix = list(self.img.getdata())
        w = self.width
        h = self.height
        return [pix[n:n+w] for n in range(0, w*h, w)]


    def get_straight_sides(self):
        straight_sides = []
        for side in ['top', 'bottom', 'left', 'right']:
            if self.is_straight_side(side):
                straight_sides.append(side)

        assert(len(straight_sides) <= 2)
        return straight_sides


    def is_straight_side(self, side):
        h = self.height
        w = self.width
        if side == 'top':
            row = self.pixels[0]
        elif side == 'bottom':
            row = self.pixels[h-1]
        elif side == 'left':
            row = [p[0] for p in self.pixels]
        elif side == 'right':
            row = [p[w-1] for p in self.pixels]
        else:
            raise ValueError("Side must be one of top, bottom, left or right")

        transparent_count = len([x for x in row if x == (0,0,0,0)])
        return transparent_count / len(row) < TRANSPARENT_ROW_PCT


    @staticmethod
    def get_piece_direction(image, side):
        """ Check which way the tabs are pointing """

        assert(side in ['left', 'right'])

        top_corner = JigsawPiece.get_end_index(image, 0, side)

        edge_indexes = []
        for i in range(0, image.height-1):
            edge_indexes.append(JigsawPiece.get_end_index(image, i, side))

        min_idx = min(edge_indexes)
        max_idx = max(edge_indexes)

        diff_top_min = abs(top_corner - min_idx)
        diff_top_max = abs(top_corner - max_idx)
        log.debug(f"TC: {top_corner}, min: {min_idx}, max: {max_idx}, mindiff: {diff_top_min}, maxdiff: {diff_top_max}")

        if diff_top_min == diff_top_max:
            return 'edge'
        elif side == 'right' and diff_top_min > diff_top_max:
            log.debug(f"{side} returning right")
            return 'left'
        elif side == 'right' and diff_top_min < diff_top_max:
            log.debug(f"{side} returning left")
            return 'right'
        elif side == 'left' and diff_top_min > diff_top_max:
            log.debug(f"{side} returning left")
            return 'left'
        elif side == 'left' and diff_top_min < diff_top_max:
            log.debug(f"{side} returning right")
            return 'right'
        else:
            log.debug(f"{side} isn't captured")
            raise ValueError()



    @staticmethod
    def get_end_index(image, row_idx, side):
        """ Get the index of the end of the image """

        assert(side in ['left', 'right'])

        row = list(reversed(image.pixels[row_idx])) \
                if side == 'right' \
                else image.pixels[row_idx]

        idx = 0
        for x_val in row[:int(image.width/3)]:
            if x_val == (0,0,0,0):
                idx += 1
                continue
            else:
                break

        return idx if side == 'left' else image.width - idx

    def do_pieces_match(self, piece):

        # Check whether a piece fits into a specified piece based on
        # the locations of the pixels
        # TODO: Currently assumes both are side/corner pieces, and have a
        # straight edge up top. This obviously won't work for middle pieces
        # TODO: Currently also assumes that `piece` fits to the left of `self`

        if self.get_piece_direction(self, 'right') != self.get_piece_direction(piece, 'left'):
            log.info("Pieces have tabs pointing in the wrong direction")
            return False

        # Get the distance from the left non-transparent edge to the end
        self_pix_dist = self.get_end_index(self, 0, 'right')
        log.debug(self_pix_dist)

        piece_pix_dist = self.get_end_index(piece, 0, 'left')

        start_idx = self_pix_dist - piece_pix_dist
        end_idx = self.width - start_idx

        output = []
        row_count = 0
        row_error = 0
        for self_row, piece_row in zip(self.pixels, piece.pixels):
            self_pix = self_row[start_idx:]
            piece_pix = piece_row[:end_idx]
            if set(self_row[start_idx-50:]) == {(0,0,0,0)} or set(piece_row[:end_idx+50]) == {(0,0,0,0)}:
                log.debug("All pixels for one batch are transparent")
                break
            log.debug(self_pix)
            log.debug("\n")
            log.debug(piece_pix)
            log.debug(row_count)
            row_count += 1
            pix_count = 0
            error_count = 0
            for self, piece in zip(self_pix, piece_pix):
                pix_count += 1
                if self == (0,0,0,0) and piece == (0,0,0,0):
                    log.debug(f"Two transparent: {self} | {piece} @{row_count}x{pix_count}")
                    if piece_row[pix_count+1] == (0,0,0,0) or self_row[pix_count+1] == (0,0,0,0):
                        error_count += 1
                    # Two transparent pixels
                elif self[3] == 255 and piece[3] == 255:
                    log.debug(f"Two non-transparent: {self} | {piece} @{row_count}x{pix_count}")
                    if piece_row[pix_count+1] != (0,0,0,0) or self_row[pix_count+1] != (0,0,0,0):
                        log.debug(self_row[pix_count+1])
                        log.debug(piece_row[pix_count+1])
                        error_count += 1
                    # Two non-transparent pixels
                else:
                    if self == (0,0,0,0):
                        log.debug(f"P: {piece}")
                        error_count = 0
                        output.append(piece)
                    else:
                        log.debug(f"S: {self}")
                        error_count = 0
                        output.append(self)

                if error_count >= 3:
                    row_error += 1


            if row_error >= 10:
                log.debug("Too many row errors")
                return False


        log.debug(output)
        img = Image.new('RGBA', (pix_count, row_count))
        log.debug(pix_count*row_count)
        log.debug(len(output))
        img.putdata(output)
        img.save('test.png')
        return True


    def fits_piece(self, piece, side):

        # Start with top row and look at joining on the left

        # Loop through current piece row by row and get the end pixels
        last_pixels = []
        for row in self.pixels:

            found_count = 0
            pixels = []
            # Keep going until the first non-transparent pixel from the end
            x = 0
            for x_val in reversed(row):

                if x_val == (0,0,0,0):
                    continue

                else:
                    # Take 7 pixels and average them
                    x += 1

                    # Skip the first pixel
                    if x == 1:
                        continue

                    # Only take 7 pixels
                    if x == 7:
                        break

                    pixels.append(x_val)

            avg_pixels = []
            for vals in zip(*pixels):
                avg_pixels.append(sum(vals)/len(vals))
            last_pixels.append(tuple(avg_pixels))

        # Do the same for the piece that's being tested
        first_pixels = []
        for row in piece.pixels:

            # Keep going until the first non-transparent pixel from the end
            x = 0
            for x_val in row:

                if x_val == (0,0,0,0):
                    continue

                else:
                    # Take 7 pixels and average them
                    x += 1

                    # Skip the first pixel
                    if x == 1:
                        continue

                    # Only take 7 pixels
                    if x == 7:
                        break

                    pixels.append(x_val)

            avg_pixels = []
            for vals in zip(*pixels):
                avg_pixels.append(sum(vals)/len(vals))
            first_pixels.append(tuple(avg_pixels))

        # Compare the values of each pixel
        pix_diff = []
        for l, r in zip(last_pixels, first_pixels):

            rgb_diff = []

            # Compare the RGB values
            for p1, p2 in zip(l, r):
                p1_pct = p1/255
                p2_pct = p2/255
                colour_diff = abs((p1_pct-p2_pct))/1
                rgb_diff.append(colour_diff)

            pix_diff.append(sum(rgb_diff)/len(rgb_diff))


        total_diff = sum(pix_diff)/len(pix_diff)
        log.debug(total_diff)
        return total_diff < PIX_DIFF_THRESHOLD


if __name__ == '__main__':
    pieces = []
    folder = "sides"
    for filename in os.listdir(folder):
        if filename.endswith(".png"):
            full_path = os.path.join(folder, filename)
            pieces.append(JigsawPiece(full_path))
        else:
            continue

    top_row = [p for p in pieces if p.is_straight and 'top' in p.straight_sides]
    bottom_row = [p for p in pieces if p.is_straight and 'bottom' in p.straight_sides]
    left_row = [p for p in pieces if p.is_straight and 'left' in p.straight_sides]
    right_row = [p for p in pieces if p.is_straight and 'right' in p.straight_sides]

    first_corner = [p for p in pieces if p.is_corner][2]
    log.info(f"First corner: {first_corner.filename} w/ {first_corner.straight_sides}")

    all_sides = [p for p in pieces if p.is_straight and not p.is_corner]
    test_side = [p for p in pieces if p.filename == 'db0b77d4d24551d35821efcb204b65dbb00957bf701643df06514a3613525e3b.png'][0]

    #log.info(first_corner.do_pieces_match(test_side))
    #exit()

    for side in all_sides:
        log.info(side.filename)
        if first_corner.do_pieces_match(side):
            log.info(f"{first_corner.filename} fits {side.filename}")

    exit()

    for piece in top_row:
        log.info(f"Top: {piece.filename} w/ {piece.straight_sides}")
    for piece in bottom_row:
        log.info(f"Bottom: {piece.filename} w/ {piece.straight_sides}")
    for piece in left_row:
        log.info(f"Left: {piece.filename} w/ {piece.straight_sides}")
    for piece in right_row:
        log.info(f"Right: {piece.filename} w/ {piece.straight_sides}")



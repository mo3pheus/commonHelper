package util;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * Created by sanketkorgaonkar on 5/12/17.
 */
public class ImageUtil extends JComponent {
    private BufferedImage image = null;

    public ImageUtil(BufferedImage image) {
        this.image = image;
    }

    public void paint(Graphics g) {
        Graphics2D g2 = (Graphics2D) g;
        g2.drawImage(image, 10, 10, this);
        g2.finalize();
    }
}

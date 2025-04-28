# Challenge #4 - ohio/beauty

Category: Ohio (OSINT)

Challenge description:

> *truly a beautiful panorama. ohio is not always ugly. i really wanna know who made this pano tho. what's their name? flag will look like: UMDCTF{Darryll Pines}*

Included photo: ![beauty](https://umdctf2025-uploads.storage.googleapis.com/uploads/cd2e52624b6a08f553bf9cd3f5eedaa77656ec963c519b1ade2c42711cf4cf47/beauty.jpg)

## Solution

Reverse image searching the tallest building in the panorama leads to LVQ apartments in Columbus, OH. This building is a 1:1 match of our building in the panorama, and shows a bridge across water near it as well.

As the panorama is in the sky, this must be a photosphere on Google Street View. Looking at the photosphere north of the bridge, directly across from LVQ apartments, this view is a 1:1 match with the provided panorama.

The poster of this photosphere is [Neil Larimore.](https://maps.app.goo.gl/VXyQyUTPn83HDUpR6)

>**Flag**: UMDCTF{Neil Larimore}
# Challenge #5 - ohio/gerard-manley-hopkins
## Writeup by Paradigm

Category: Ohio (OSINT) 

Challenge description:

> *as kingfishers catch fire, dragonflies draw flame; as tumbled over rim in roundy wells stones ring; like each tucked string tells, each hung bell's bow swung finds tongue to fling out broad its name; each mortal thing does one thing and the same: deals out that being indoors each one dwells; selves - goes itself; myself it speaks and spells, crying what i do is me: for that i came. i say more: the just man justices; keeps grace: that keeps all his goings graces; acts in god's eye what in god's eye he is - christ - for christ plays in ten thousand places, lovely in limbs, and lovely in eyes not his to the father through the feature of men's faces. sorry i just really like poetry. what road are we on? flag will look like: UMDCTF{Campus Dr, College Park, MD 20742}*

Included photo: ![gerard-manley-hopkins](gerard-manley-hopkins.jpg)

## Solution

*Co-solved with [@Starglow](https://github.com/jacksonjost)*

Gerard Manley Hopkins is an English Poet. He wrote the poem "As Kingfishers Catch Fire" in 1877, which is when he lived in a pastoral town in Wales. Kingfishers are birds that live near water, as they are known for their ability to dive and catch fish.

Visually in the panorama, we see a trash can with "Dailey's" and a phone number. Searching the phone number brings up Dailey's Recycling in Wellsville, OH.

Given the references to a pastoral town near water in Ohio along with the Dailey's reference, Wellsville is our match.

As per Starglow:
> *Looking at house 1116 on the left, it seems that it was painted more recently, perhaps to be sold. By searching the house number with what we know (Wellsville) we get an immediate hit on Zillow for the address, of which we narrow down between Esther Ave and Hillcrest Rd. We determined that it was Hillcrest.*

Note: Both 1121 and 1116 and "Wellsville" are great searches to find the location of this street view.

[Here's the location's street view!](https://maps.app.goo.gl/tGHADEtY1ioYECzMA)

>**Flag**: UMDCTF{Hillcrest Rd, Wellsville, OH 43968}

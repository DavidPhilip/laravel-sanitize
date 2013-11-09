<?php

namespace Webpatser\Sanitize;

class Sanitize {

    /**
     * Sanitizes a string, replacing whitespace and a few other characters with dashes.
     *
     * Limits the output to alphanumeric characters, underscore (_) and dash (-).
     * Whitespace becomes a dash.
     *
     * @param string $string The string to be sanitized.
     * @return string The sanitized string.
     */
    public static function string( $string = null ) {
        if (empty($string)) {
            throw new \InvalidArgumentException('No input string is given');
        }

        $string = strip_tags($string);
        /*// Preserve escaped octets.
        $string = preg_replace('|%([a-fA-F0-9][a-fA-F0-9])|', '---$1---', $string);

        // Remove percent signs that are not part of an octet.
        $string = str_replace('%', '', $string);

        // Restore octets.
        $string = preg_replace('|---([a-fA-F0-9][a-fA-F0-9])---|', '%$1', $string);
*/
        // maps German (umlauts) and other European characters onto two characters before just removing diacritics
        $string    = preg_replace( '@\x{00c4}@u'    , "AE",    $string );    // umlaut Ä => AE
        $string    = preg_replace( '@\x{00d6}@u'    , "OE",    $string );    // umlaut Ö => OE
        $string    = preg_replace( '@\x{00dc}@u'    , "UE",    $string );    // umlaut Ü => UE
        $string    = preg_replace( '@\x{00e4}@u'    , "ae",    $string );    // umlaut ä => ae
        $string    = preg_replace( '@\x{00f6}@u'    , "oe",    $string );    // umlaut ö => oe
        $string    = preg_replace( '@\x{00fc}@u'    , "ue",    $string );    // umlaut ü => ue
        $string    = preg_replace( '@\x{00f1}@u'    , "ny",    $string );    // ñ => ny
        $string    = preg_replace( '@\x{00ff}@u'    , "yu",    $string );    // ÿ => yu
        
        
        // maps special characters (characters with diacritics) on their base-character followed by the diacritical mark
        // exmaple:  Ú => U´,  á => a`
        $string    = \Normalizer::normalize( $string, \Normalizer::FORM_D );
        
        
        $string    = preg_replace( '@\pM@u'        , "",    $string );       // removes diacritics
        
        
        $string    = preg_replace( '@\x{00df}@u'    , "ss",    $string );    // maps German ß onto ss
        $string    = preg_replace( '@\x{00c6}@u'    , "AE",    $string );    // Æ => AE
        $string    = preg_replace( '@\x{00e6}@u'    , "ae",    $string );    // æ => ae
        $string    = preg_replace( '@\x{0132}@u'    , "IJ",    $string );    // ? => IJ
        $string    = preg_replace( '@\x{0133}@u'    , "ij",    $string );    // ? => ij
        $string    = preg_replace( '@\x{0152}@u'    , "OE",    $string );    // Œ => OE
        $string    = preg_replace( '@\x{0153}@u'    , "oe",    $string );    // œ => oe
        
        $string    = preg_replace( '@\x{00d0}@u'    , "D",    $string );    // Ð => D
        $string    = preg_replace( '@\x{0110}@u'    , "D",    $string );    // Ð => D
        $string    = preg_replace( '@\x{00f0}@u'    , "d",    $string );    // ð => d
        $string    = preg_replace( '@\x{0111}@u'    , "d",    $string );    // d => d
        $string    = preg_replace( '@\x{0126}@u'    , "H",    $string );    // H => H
        $string    = preg_replace( '@\x{0127}@u'    , "h",    $string );    // h => h
        $string    = preg_replace( '@\x{0131}@u'    , "i",    $string );    // i => i
        $string    = preg_replace( '@\x{0138}@u'    , "k",    $string );    // ? => k
        $string    = preg_replace( '@\x{013f}@u'    , "L",    $string );    // ? => L
        $string    = preg_replace( '@\x{0141}@u'    , "L",    $string );    // L => L
        $string    = preg_replace( '@\x{0140}@u'    , "l",    $string );    // ? => l
        $string    = preg_replace( '@\x{0142}@u'    , "l",    $string );    // l => l
        $string    = preg_replace( '@\x{014a}@u'    , "N",    $string );    // ? => N
        $string    = preg_replace( '@\x{0149}@u'    , "n",    $string );    // ? => n
        $string    = preg_replace( '@\x{014b}@u'    , "n",    $string );    // ? => n
        $string    = preg_replace( '@\x{00d8}@u'    , "O",    $string );    // Ø => O
        $string    = preg_replace( '@\x{00f8}@u'    , "o",    $string );    // ø => o
        $string    = preg_replace( '@\x{017f}@u'    , "s",    $string );    // ? => s
        $string    = preg_replace( '@\x{00de}@u'    , "T",    $string );    // Þ => T
        $string    = preg_replace( '@\x{0166}@u'    , "T",    $string );    // T => T
        $string    = preg_replace( '@\x{00fe}@u'    , "t",    $string );    // þ => t
        $string    = preg_replace( '@\x{0167}@u'    , "t",    $string );    // t => t
        
        // remove all non-ASCii characters
        $string    = preg_replace( '@[^\0-\x80]@u'    , "",    $string ); 
        $string    = preg_replace( '/-/'    , "",    $string ); 
        
        if (function_exists('mb_strtoupper')) {
            $string = mb_strtoupper($string, 'UTF-8');
        } else {
            $string = strtoupper($string);
        }

        return $string;
    }
} 
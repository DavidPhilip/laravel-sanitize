<?php

use Illuminate\Support\Facades\Facade;

/**
 * SanitizeFacade
 *
 */ 
class SanitizeFacade extends Facade {
 
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor() {
        return 'midgardmvc_helper_urlize';
    }
 
}
<?php


namespace Apadana\Auth_armj\Logger;


use DateTime;
use Illuminate\Support\Facades\Log;

class ApadanaLogger
{
    const Log_separator = " ";

    /**
     * @param $message
     */
    public static function info($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [info]".
            self::Log_separator . $message;

        Log::info( $log_message );
    }

    /**
     * @param $message
     */
    public static function debug($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [debug]".
            self::Log_separator . $message;

        Log::debug( $log_message );
    }

    /**
     * @param $message
     */
    public static function error($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [error]".
            self::Log_separator . $message;

        Log::error( $log_message );
    }

    /**
     * @param $message
     */
    public static function critical($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [critical]".
            self::Log_separator . $message;

        Log::critical( $log_message );
    }

    /**
     * @param $message
     */
    public static function warning($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [warning]".
            self::Log_separator . $message;

        Log::warning( $log_message );
    }

    /**
     * @param $message
     */
    public static function notice($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [notice]".
            self::Log_separator . $message;

        Log::notice( $log_message );
    }

    /**
     * @param $message
     */
    public static function emergency($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [emergency]".
            self::Log_separator . $message;

        Log::emergency( $log_message );
    }

    /**
     * @param $message
     */
    public static function alert($message)
    {
        $now = new DateTime();
        $app_name = str_replace(" ", "-", strtolower(config('app.name')) );
        $log_message = $now->format("M d H:i:s") . self::Log_separator .
            gethostname() . self::Log_separator . $app_name .": [alert]".
            self::Log_separator . $message;

        Log::alert( $log_message );
    }

}

<?php

namespace App\Notifications\Telegram;

use RuntimeException;

/**
 * The Bot API refused a request, or could not be reached (code 0).
 */
class TelegramException extends RuntimeException
{
    /**
     * @param  ?int  $retryAfter  seconds to wait before the next request, when Telegram limits the bot's rate
     */
    public function __construct(string $message, int $code = 0, public readonly ?int $retryAfter = null)
    {
        parent::__construct($message, $code);
    }

    /**
     * Whether the chat cannot get messages any more: the user blocked the bot or deleted their account.
     * Sending there again is pointless, unlike after a network error or a rate limit.
     */
    public function isChatUnavailable(): bool
    {
        return $this->getCode() === 403
            || ($this->getCode() === 400 && str_contains(mb_strtolower($this->getMessage()), 'chat not found'));
    }
}

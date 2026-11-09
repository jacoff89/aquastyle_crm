<?php

namespace App\Actions;

use App\Models\User;
use App\Notifications\Telegram\TelegramBot;
use App\Notifications\Telegram\TelegramException;
use App\Notifications\Telegram\TelegramLinkTokens;

/**
 * Reacts to what people send the bot, whether the update came to the webhook or was polled.
 *
 * "/start <token>" from the link on the settings page links the chat to that account; "/stop"
 * unlinks it, and so does blocking the bot. Only private chats count: notices are personal.
 * Anything else gets a hint on how to connect.
 */
class HandleTelegramUpdate
{
    /**
     * The kinds of updates the bot asks Telegram for.
     */
    public const ALLOWED_UPDATES = ['message', 'my_chat_member'];

    private const SETTINGS_HINT = 'в CRM на странице «Уведомления → Настройки»';

    public function __construct(private TelegramBot $bot, private TelegramLinkTokens $tokens) {}

    /**
     * @param  array<string, mixed>  $update  an Update object of the Bot API
     */
    public function handle(array $update): void
    {
        if (isset($update['my_chat_member'])) {
            $this->handleMembership($update['my_chat_member']);

            return;
        }

        $message = $update['message'] ?? null;

        if (! is_array($message) || ($message['chat']['type'] ?? null) !== 'private' || ! isset($message['chat']['id'])) {
            return;
        }

        $chatId = (int) $message['chat']['id'];
        $text = trim((string) ($message['text'] ?? ''));

        $reply = match (true) {
            preg_match('/^\/start(?:@\w+)?\s+(\S+)$/u', $text, $matches) === 1 => $this->link($chatId, $matches[1], $message['from']['username'] ?? null),
            preg_match('/^\/stop(?:@\w+)?$/u', $text) === 1 => $this->unlink($chatId),
            default => $this->status($chatId),
        };

        $this->reply($chatId, $reply);
    }

    /**
     * The user blocked the bot: there is nowhere to send notices any more.
     *
     * @param  array<string, mixed>  $membership
     */
    private function handleMembership(array $membership): void
    {
        if (($membership['new_chat_member']['status'] ?? null) === 'kicked' && isset($membership['chat']['id'])) {
            $this->userOfChat((int) $membership['chat']['id'])?->unlinkTelegram();
        }
    }

    private function link(int $chatId, string $token, ?string $username): string
    {
        $user = $this->tokens->consume($token);

        if ($user === null) {
            return 'Ссылка устарела или уже использована. Нажмите «Подключить Telegram» '.self::SETTINGS_HINT.' ещё раз.';
        }

        $user->linkTelegram($chatId, $username);

        return "Готово! Уведомления CRM для {$user->fullName()} будут приходить сюда.\n\n"
            .'Какие именно — выбирается '.self::SETTINGS_HINT.'. Отключить уведомления: /stop';
    }

    private function unlink(int $chatId): string
    {
        $user = $this->userOfChat($chatId);

        if ($user === null) {
            return $this->status($chatId);
        }

        $user->unlinkTelegram();

        return 'Уведомления отключены. Подключить их снова можно '.self::SETTINGS_HINT.'.';
    }

    private function status(int $chatId): string
    {
        $user = $this->userOfChat($chatId);

        if ($user !== null) {
            return "Этот чат получает уведомления CRM для {$user->fullName()}. Отключить: /stop";
        }

        return 'Чтобы получать сюда уведомления CRM, нажмите «Подключить Telegram» '.self::SETTINGS_HINT.'.';
    }

    private function userOfChat(int $chatId): ?User
    {
        return User::query()->where('telegram_chat_id', $chatId)->first();
    }

    /**
     * Answer in the chat. The update is handled whether or not the answer gets through,
     * so a failure is only reported.
     */
    private function reply(int $chatId, string $text): void
    {
        try {
            $this->bot->sendMessage($chatId, e($text));
        } catch (TelegramException $exception) {
            report($exception);
        }
    }
}

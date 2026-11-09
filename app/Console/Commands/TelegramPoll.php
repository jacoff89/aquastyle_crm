<?php

namespace App\Console\Commands;

use App\Actions\HandleTelegramUpdate;
use App\Notifications\Telegram\TelegramBot;
use App\Notifications\Telegram\TelegramException;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

/**
 * Fetches the bot's updates instead of the webhook, for a machine Telegram cannot post to,
 * such as a local installation. It works only while the bot has no webhook (telegram:webhook --delete).
 */
#[Signature('telegram:poll
    {--once : Забрать накопившиеся обновления и выйти}')]
#[Description('Получать обновления Telegram-бота без webhook (для локальной разработки)')]
class TelegramPoll extends Command
{
    private const WAIT_SECONDS = 25;

    private bool $shouldStop = false;

    public function handle(TelegramBot $bot, HandleTelegramUpdate $handleUpdate): int
    {
        if (! $bot->isConfigured()) {
            $this->error('Бот не настроен: задайте TELEGRAM_BOT_TOKEN и TELEGRAM_BOT_USERNAME в .env.');

            return self::FAILURE;
        }

        $this->trap([SIGINT, SIGTERM], fn () => $this->shouldStop = true);
        $this->info('Жду сообщения боту. Остановить: Ctrl+C.');

        $offset = 0;

        do {
            try {
                $updates = $bot->getUpdates($offset, $this->option('once') ? 0 : self::WAIT_SECONDS, HandleTelegramUpdate::ALLOWED_UPDATES);
            } catch (TelegramException $exception) {
                $this->error("Telegram ответил ошибкой: {$exception->getMessage()}");

                if ($exception->getCode() === 409) {
                    $this->line('У бота подключён webhook. Отключите его: php artisan telegram:webhook --delete');
                }

                return self::FAILURE;
            }

            foreach ($updates as $update) {
                $offset = (int) $update['update_id'] + 1;
                $handleUpdate->handle($update);
                $this->line('Обработано обновление '.$update['update_id']);
            }
        } while (! $this->option('once') && ! $this->shouldStop);

        if ($offset > 0) {
            // Confirm the last handled updates, so that Telegram does not return them on the next run.
            $bot->getUpdates($offset, 0, HandleTelegramUpdate::ALLOWED_UPDATES);
        }

        return self::SUCCESS;
    }
}

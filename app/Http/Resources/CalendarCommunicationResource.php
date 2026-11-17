<?php

namespace App\Http\Resources;

use App\Enums\CommunicationStatus;
use App\Http\Requests\Events\EventRequest;
use App\Models\Communication;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Str;

/**
 * A communication as the communications calendar shows it. Expects `client` and `creator` to be loaded.
 *
 * A communication is a moment, not a period: `end` is set DURATION_MINUTES after `start`
 * only so the calendar has a block to draw in the week and day views.
 *
 * `isPlanned` tells the calendar to mark the communication red once its time has passed;
 * the calendar checks the time itself, so the mark appears without a reload.
 *
 * @mixin Communication
 */
class CalendarCommunicationResource extends JsonResource
{
    public const DURATION_MINUTES = 30;

    private const NOTES_LIMIT = 120;

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'clientId' => $this->client_id,
            'clientName' => $this->client->fullName(),
            'channel' => $this->channel->value,
            'channelLabel' => $this->channel->label(),
            'status' => $this->status->value,
            'statusLabel' => $this->status->label(),
            'isPlanned' => $this->status === CommunicationStatus::Planned,
            'start' => $this->occurred_at->format(EventRequest::DATETIME_FORMAT),
            'end' => $this->occurred_at->copy()->addMinutes(self::DURATION_MINUTES)->format(EventRequest::DATETIME_FORMAT),
            'notes' => Str::limit($this->notes, self::NOTES_LIMIT),
            'creatorId' => $this->created_by,
            'creatorName' => $this->creator?->name,
            'color' => $this->creator?->color,
        ];
    }
}
